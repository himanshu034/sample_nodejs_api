"""
=============================================================================
COPYRIGHT NOTICE
=============================================================================
© Copyright HCL Technologies Ltd. 2021, 2022, 2023, 2024, 2025
Proprietary and confidential. All information contained herein is, and
remains the property of HCL Technologies Limited. Copying or reproducing the
contents of this file, via any medium is strictly prohibited unless prior
written permission is obtained from HCL Technologies Limited.
"""

import requests
import datetime
from pathlib import Path
from typing import List

import aiforce_xl.exception_handler as exp
from aiforce_xl.logging_handler import (
    get_logger,
    log_function_call,
    decorate_all_methods,
)
from sqlalchemy import select, func, literal, and_, not_
from aiforce_xl.db_handler import get_env_or_ini
from aiforce_xl.authorization import UserInfo, get_user_info
from aiforce_xl.config_handler import load_config
from aiforce_xl.security_handler import get_password_hash
from sqlalchemy import func
from sqlalchemy.sql import literal
from sqlmodel import select

from app.core.data_helper.db_manager import get_db_session
from app.messages import user_messages as msg
from app.models.roles import Roles
from app.models.user_project_role_view import UserProjectRoleAggView
from app.models.users import UserProjects, Users
from app.repositories.role_repository import RoleRepository
from app.repositories.role_type_repository import RoleTypeRepository
from app.repositories.user_repository import UserRepository
from app.schema.user_project_permissions_schema import (
    ProjectPermissionSchema,
    UserProjectPermissionsResponse,
)
from app.schema.user_schema import (
    CreateUserRequest,
    CreateUserResponse,
    DeleteUserResponse,
    InviteUserRequest,
    InviteUserResponse,
    RemoveInvitedUserRequest,
    RemoveInvitedUserResponse,
    validate_user_name,
    validate_email_format,
    UserResponse,
    UserListResponse,
    UpdateUserRequest,
    UpdateUserResponse,
    UserSearchSuggestion,
    UserSearchResponse,
    UserInfoResponse,
)
from app.core.data_helper.vault_manager import get_vault_handler


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE_PATH = BASE_DIR / "config" / "config.ini"
config = load_config(config_file_path=CONFIG_FILE_PATH)


@decorate_all_methods(log_function_call)
class UserService:
    """
    Service class for handling authentication operations such as user sign-in and token generation.
    """

    logger = get_logger("UserService")

    def __init__(self):
        """
        Initializes the AuthService instance.

        This constructor sets up the user repository by creating an instance
        of the UserRepository class, which is used to manage user-related
        operations.
        """
        self.user_repository = UserRepository()
        self.logger = get_logger("UserService")

    def _get_keycloak_config(self):
        """
        Retrieves Keycloak configuration from the global config.

        Returns:
            dict: Keycloak configuration.
        """
        keyclock_config: dict = {
            "server_url": get_env_or_ini(config, "KC_SERVER_URL", "keycloak", "server_url"),
            "client_id": get_env_or_ini(config, "KC_CLIENT_ID", "keycloak", "client_id"),
            "realm_name": get_env_or_ini(config, "KC_REALM_NAME", "keycloak", "realm_name"),
            "client_secret": get_env_or_ini(
                config, "KC_CLIENT_SECRET", "keycloak", "client_secret"
            ),
            "redirect_uri": get_env_or_ini(config, "KC_REDIRECT_URI", "keycloak", "redirect_uri"),
            "is_enabled": get_env_or_ini(config, "KC_ENABLE", "keycloak", "is_enabled"),
        }
        return keyclock_config

    def _get_admin_access_token(self, keycloak_cfg):
        """
        Retrieves an admin access token from Keycloak.

        Args:
            keycloak_cfg (dict): Keycloak configuration.

        Returns:
            str: Access token.

        Raises:
            ServiceUnavailableError: If unable to retrieve the access token.
        """
        try:
            token_url = f"{keycloak_cfg['server_url']}/realms/{keycloak_cfg['realm_name']}/protocol/openid-connect/token"
            token_data = {
                "grant_type": "client_credentials",
                "client_id": keycloak_cfg["client_id"],
                "client_secret": keycloak_cfg["client_secret"],
            }
            token_resp = requests.post(token_url, data=token_data, verify=False)
            token_resp.raise_for_status()
            access_token = token_resp.json().get("access_token")

            if not access_token:
                raise exp.ServiceUnavailableError(detail="Failed to retrieve Keycloak access token")

            return access_token
        except requests.RequestException as e:
            raise exp.ServiceUnavailableError(
                detail=f"Error retrieving Keycloak access token: {str(e)}"
            )

    async def create_user_keycloak(self, kc_user_info: dict) -> None:
        """
        Creates a user in Keycloak using client credentials.

        Args:
            kc_user_info (dict): User payload to send to Keycloak.

        Raises:
            ServiceUnavailableError: If connection to Keycloak fails.
            InternalServerError: For any unexpected errors.
        """
        try:
            keycloak_cfg = self._get_keycloak_config()
            access_token = self._get_admin_access_token(keycloak_cfg)

            # Step 2: Create user
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            create_user_url = (
                f"{keycloak_cfg['server_url']}/admin/realms/{keycloak_cfg['realm_name']}/users"
            )
            resp = requests.post(create_user_url, json=kc_user_info, headers=headers, verify=False)

            if resp.status_code == 201:
                print("✅ User created successfully in Keycloak.")
            elif resp.status_code == 409:
                print("⚠️ User already exists in Keycloak.")
            else:
                raise exp.InternalServerError(detail=f"Keycloak user creation failed: {resp.text}")

        except requests.RequestException as e:
            raise exp.InternalServerError(detail=f"Error creating user in Keycloak: {str(e)}")

    async def delete_user_keycloak(self, username: str) -> None:
        """
        Deletes a user in Keycloak by username.

        Args:
            username (str): Username of the user to delete.

        Raises:
            InternalServerError: For any unexpected errors.
        """
        try:
            keycloak_cfg = self._get_keycloak_config()
            access_token = self._get_admin_access_token(keycloak_cfg)

            # Step 1: Search for user by username
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            search_url = (
                f"{keycloak_cfg['server_url']}/admin/realms/{keycloak_cfg['realm_name']}/users"
            )
            params = {"username": username}
            resp = requests.get(search_url, headers=headers, params=params, verify=False)

            if resp.status_code != 200:
                raise exp.InternalServerError(detail=f"Failed to search user: {resp.text}")

            users = resp.json()
            if not users:
                print(f"User '{username}' not found.")
                return

            user_id = users[0]["id"]

            # Step 2: Delete user
            delete_url = f"{keycloak_cfg['server_url']}/admin/realms/{keycloak_cfg['realm_name']}/users/{user_id}"
            del_resp = requests.delete(delete_url, headers=headers, verify=False)

            if del_resp.status_code == 204:
                print(f"✅ User '{username}' deleted successfully.")
            else:
                raise exp.InternalServerError(detail=f"Failed to delete user: {del_resp.text}")

        except requests.RequestException as e:
            raise exp.InternalServerError(detail=f"Error deleting user in Keycloak: {str(e)}")

    async def validate_duplicate_email(self, email_id: str) -> None:
        """
        Checks if the given email_id already exists in the Users table (case-insensitive).
        Raises DuplicatedError if a user with the same email_id exists.
        """
        existing_users = await self.user_repository.search_user(email_id)
        email_id_lower = email_id.lower()
        for user in existing_users:
            user_email = getattr(user, "email_id", None)
            if user_email and user_email.lower() == email_id_lower:
                raise exp.DuplicatedError(detail=msg.USER_EMAIL_ALREADY_EXISTS)

    async def create_user(self, user_info: CreateUserRequest) -> CreateUserResponse:
        """
        Creates a new user along with their role and project mapping.

        Args:
            user_info (CreateUserRequest): Data required to create a new user.
            login_user_info (dict): Decoded user info from token.

        Returns:
            CreateUserResponse: The response containing the ID of the newly created user.

        Raises:
            DuplicatedError: If a user with the same username already exists.
        """
        # Validate user_name, email_id
        vault_handler = get_vault_handler()
        if not user_info.user_name or not str(user_info.user_name).strip():
            raise exp.NotAcceptableError(detail=msg.MISSING_USERNAME)
        validate_user_name(user_info.user_name)
        if user_info.email_id:
            validate_email_format(user_info.email_id)
            await self.validate_duplicate_email(user_info.email_id)

        login_user_info = get_user_info()
        if dict(config["keycloak"])["is_enabled"] == "True":
            kc_user_info = {
                "username": user_info.user_name,
                "enabled": True,
                "email": user_info.email_id,
                "firstName": user_info.first_name,
                "lastName": user_info.last_name,
                "credentials": [
                    {
                        "type": "password",
                        "value": user_info.password,
                        "temporary": False,
                    }
                ],
            }
            await self.create_user_keycloak(kc_user_info)
        login_user_id = login_user_info.user_id
        org_id = login_user_info.org_id
        existing_user = await self.user_repository.get_user_by_name(user_info.user_name)

        if existing_user:
            raise exp.DuplicatedError(detail=msg.USER_ALREADY_EXISTS)

        hashed_password = get_password_hash(user_info.password)
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode("utf-8")

        vault_config_value = None
        if dict(config["keycloak"])["is_enabled"] == "False":
            if vault_handler and vault_handler.use_vault:
                vault_config_value = hashed_password
                hashed_password = None
        new_user = Users(
            user_name=user_info.user_name,
            first_name=user_info.first_name,
            last_name=user_info.last_name,
            email_id=user_info.email_id,
            password=hashed_password,
            is_active=user_info.is_active,
            created_at=datetime.datetime.now(),
            created_by=login_user_id,
            org_id=org_id,
            role_id=user_info.role_type,
            vault_enabled=bool(vault_config_value),
        )
        await self.user_repository.add_user(new_user)

        if dict(config["keycloak"])["is_enabled"] == "False":
            if vault_handler and vault_handler.use_vault:
                vault_key = f"{new_user.id}__user__password"
                if vault_config_value:
                    self.logger.info("Vault started saving password for PMS.")
                    vault_config = vault_handler.save_json_secret(vault_key, vault_config_value)
                    if not vault_config:
                        # If saving to Vault failed, rollback the saved user
                        await self.user_repository.delete_users(
                            new_user.id, login_user_info.project_id
                        )
                        raise exp.InternalServerError(
                            detail="Failed to save password to Vault. User creation has been rolled back."
                        )

                    self.logger.info("Vault finished saving password for PMS.")
        return CreateUserResponse(user_id=new_user.id)

    async def list_user(
        self,
        page_number: int,
        page_size: int,
        search_term: str,
        superadmin: bool = False,
    ) -> List[UserResponse]:
        """
        Lists users associated with a specific project.


        Args:
            project_id (int): The ID of the project to list users for.

        Returns:
            List[UserResponse]: A list of user response objects.

        Raises:
            AuthError: If no users are found for the project.
        """
        login_user_info: UserInfo = get_user_info()
        project_id = login_user_info.project_id
        result = await self.user_repository.list_user(
            project_id, page_number, page_size, search_term, superadmin
        )
        if not result:
            self.logger.info("No users found for project_id: %s", project_id)
            return UserListResponse(users=[], total_count=0)
        current_time = datetime.datetime.now(datetime.timezone.utc)
        updated_users = []
        for user in result["users"]:
            user_dict = dict(user)
            # Ensure project_ids is present and project_id is not
            if "project_id" in user_dict:
                user_dict.pop("project_id")
            if "project_ids" not in user_dict:
                user_dict["project_ids"] = []
            last_active = user_dict.get("last_active")
            if last_active:
                time_diff = current_time - last_active
                if time_diff.days >= 30:
                    user_dict["last_active"] = f"{time_diff.days // 30} months ago"
                elif time_diff.days >= 1:
                    user_dict["last_active"] = f"{time_diff.days} days ago"
                elif time_diff.seconds >= 3600:
                    user_dict["last_active"] = f"{time_diff.seconds // 3600} hrs ago"
                elif time_diff.seconds >= 60:
                    user_dict["last_active"] = f"{time_diff.seconds // 60} mins ago"
                else:
                    user_dict["last_active"] = "Just now"
            else:
                user_dict["last_active"] = "NA"
                # Only keep role_id and role_type in response
                user_dict = {
                    k: v
                    for k, v in user_dict.items()
                    if k
                    in [
                        "user_id",
                        "user_name",
                        "first_name",
                        "last_name",
                        "email_id",
                        "is_active",
                        "last_active",
                        "role_id",
                        "is_super_admin",
                        "role_type",
                        "role_type_name",
                    ]
                }
            updated_users.append(user_dict)

        # Ensure every user dict has project_id (default 0 if missing)
        for user in updated_users:
            if "project_id" not in user or user["project_id"] is None:
                user["project_id"] = 0
        return UserListResponse(users=updated_users, total_count=result["total_count"])

    async def update_user(
        self, user_info: UpdateUserRequest, login_user_info
    ) -> UpdateUserResponse:
        """
        Updates an existing user's information including project and role mappings.

        Args:
            sign_in_info (UpdateUserRequest): Updated user information.

        Returns:
            UpdateUserResponse: The response containing the ID of the updated user.

        Raises:
            AuthError: If the user is not found.
            DuplicatedError: If the updated username is already taken by another user.
            BadRequestError: If a non-editable field is attempted to be changed.
        """
        user = await self.user_repository.get_user_by_id(user_info.user_id)
        login_user_id = login_user_info.user_id
        if not user:
            raise exp.AuthError(detail=msg.USER_NOT_FOUND)

        if user_info.role_id == 1:
            raise exp.BadRequestError(detail="Role Id cannot be updated to 1 or Super Admin")
        if login_user_info.user_id == user_info.user_id:
            raise exp.BadRequestError(detail="User cannot update itself")
        user_project_exists = await self.user_repository.user_project_mapping_exists(
            user_id=user_info.user_id, project_id=login_user_info.project_id
        )
        if not login_user_info.is_super_admin:
            if not user_project_exists:
                self.logger.error(
                    f"Update denied: login_user_id={login_user_id} does not have permission to update user_id={user_info.user_id}"
                )
                raise exp.AuthError(detail=msg.UNAUTHORIZED_USER_UPDATE)
        # Block updates to non-editable fields
        non_editable_fields = [
            ("user_name", user_info.user_name, user.user_name),
            ("first_name", user_info.first_name, user.first_name),
            ("last_name", user_info.last_name, user.last_name),
            ("email_id", user_info.email_id, user.email_id),
        ]
        changed_fields = [field for field, new, old in non_editable_fields if new != old]
        if changed_fields:
            raise exp.BadRequestError(
                detail=f"The following fields cannot be updated: {', '.join(changed_fields)}"
            )

        # Check if role_id exists in roles table
        role_repo = RoleRepository()
        role = await role_repo.get_role_by_id(user_info.role_id)
        # If not found, use role_type from payload (if present) or fallback to role_id
        role_type_value = getattr(user_info, "role_type", None)
        role_type_id = role_type_value if role_type_value else user_info.role_id
        if not role and role_type_id:
            raise exp.BadRequestError(detail="Role or Role Type Id does not exist")

        self.logger.info(
            f"Proceeding with update: user_id={user_info.user_id}, role_id={user_info.role_id}, role_type={role_type_value}"
        )
        update_data = {
            # non-editable fields are not included for update
            "is_active": user_info.is_active,
            "modified_at": datetime.datetime.now(),
            "modified_by": login_user_id,
            "role_id": user_info.role_id,
        }
        self.logger.info(f"Update data: {update_data}")
        updated_user_project_mapping = {
            "user_id": user_info.user_id,
            "project_id": login_user_info.project_id,
            "role_id": user_info.role_id,
            "modified_by": login_user_id,
            "modified_at": datetime.datetime.now(),
        }
        self.logger.info(f"User project mapping: {updated_user_project_mapping}")
        await self.user_repository.update_user(
            user_info.user_id, update_data, updated_user_project_mapping
        )
        return UpdateUserResponse(user_id=user_info.user_id)

    async def delete_user(self, user_id: int) -> DeleteUserResponse:
        """
        Deletes a user by their ID after checking for associated project references.

        Args:
            sign_in_info (DeleteUserRequest): Contains the ID of the user to be deleted.

        Returns:
            DeleteUserResponse: A response indicating successful deletion.

        Raises:
            AuthError: If the user is not found or still has project references.
        """
        login_user_info: UserInfo = get_user_info()
        if not login_user_info.is_super_admin:
            raise exp.BadRequestError(detail="You are not authorized to delete user.")
        user_details = await self.user_repository.get_user_by_id(user_id)
        if not user_details:
            raise exp.NotFoundError(detail=msg.USER_NOT_FOUND)
        if dict(config["keycloak"])["is_enabled"] == "True":
            await self.delete_user_keycloak(user_details.user_name)
        project_id = login_user_info.project_id
        if user_details.user_name in ["superadmin", "admin"]:
            raise exp.BadRequestError(detail="Admin Users cannot be deleted")

        await self.user_repository.delete_users(user_id, project_id)
        return DeleteUserResponse(is_deleted=True)

    async def remove_invited_user(
        self, sign_in_info: RemoveInvitedUserRequest
    ) -> RemoveInvitedUserResponse:
        """
        Removes an invited user from the system based on user ID.

        Args:
            sign_in_info (RemoveInvitedUserRequest): Contains the ID of the invited user to remove.

        Returns:
            RemoveInvitedUserResponse: A response indicating successful removal.
        """
        login_user_info: UserInfo = get_user_info()
        project_id = login_user_info.project_id
        user_id = sign_in_info.user_id

        await self.user_repository.remove_invited_users(user_id, project_id)

    async def invite_user(self, sign_in_info: InviteUserRequest) -> InviteUserResponse:
        """
        Invites multiple users by creating or updating project associations marked as invited.
        If user is already in the project, update their role and is_invited status.
        Only saves UserProjects for each email (does not create new Users).

        Args:
            sign_in_info (InviteUserRequest): Data required to invite users.

        Returns:
            InviteUserResponse: The response containing the list of invited emails.
        """
        invited_emails = []
        invited_ids = []
        existing_users = []
        login_user_info: UserInfo = get_user_info()
        user_id: int = login_user_info.user_id
        project_id: int = login_user_info.project_id
        for email in sign_in_info.emails:
            # Find user by email
            users = await self.user_repository.search_user(email)
            user_obj = None
            for u in users:
                if u.email_id == email:
                    user_obj = u
                    break
            print("user_obj", user_obj)
            if not user_obj:
                continue  # Skip if user does not exist
            # Check if user already in project
            user_projects = await self.user_repository.get_user_reference(
                user_obj.id
            )
            in_project = None
            for up in user_projects:
                if up.project_id == project_id:
                    in_project = up
                    break
            if in_project:
                # Check if already invited with the same role
                if getattr(in_project, "is_invited", False) and getattr(in_project, "role_id", None) == sign_in_info.role:
                    existing_users.append(email)
                    continue
                # Update role and is_invited status
                await self.user_repository.update_user_project_role(
                    user_obj.id,
                    project_id,
                    sign_in_info.role,
                    is_invited=True
                )
                invited_emails.append(email)
                continue
            # Check if this is the first invited project for the user
            has_any_project = len(user_projects) > 0
            is_default = not has_any_project
            invited_user_project_mapping = UserProjects(
                user_id=user_obj.id,
                project_id=project_id,
                role_id=sign_in_info.role,
                is_invited=True,
                created_by=user_id,
                created_at=datetime.datetime.now(),
                is_default=is_default,
            )
            await self.user_repository.invite_user(invited_user_project_mapping)
            invited_emails.append(email)
            invited_ids.append(user_obj.id)
        return InviteUserResponse(existing_users=existing_users, invited_users=invited_ids)

    async def search_user(self, query: str):
        """
        Real-time search for users by username or email (case-insensitive, partial match).
        Returns UserSearchResponse schema.
        """
        query_lower = query.lower()
        users = await self.user_repository.search_user(query)
        filtered_users = []
        for u in users:
            user_name = getattr(u, "user_name", "")
            email_id = getattr(u, "email_id", "")
            if query_lower in user_name.lower() or query_lower in email_id.lower():
                filtered_users.append(UserSearchSuggestion(user_name=user_name, email_id=email_id))
        return UserSearchResponse(users=filtered_users)

    async def create_azure_user(self, user_info: dict) -> CreateUserResponse:
        """
        Creates a new user along with their role and project mapping.

        Args:
            user_info (CreateUserRequest): Data required to create a new user.
            login_user_info (dict): Decoded user info from token.

        Returns:
            CreateUserResponse: The response containing the ID of the newly created user.

        Raises:
            DuplicatedError: If a user with the same username already exists.
        """
        existing_user = await self.user_repository.get_user_by_name(user_info["user_name"])

        if existing_user:
            raise exp.DuplicatedError(detail=msg.USER_ALREADY_EXISTS)

        hashed_password = get_password_hash(user_info["password"])
        if isinstance(hashed_password, bytes):
            hashed_password = hashed_password.decode("utf-8")

        new_user = Users(
            user_name=user_info["user_name"],
            email_id=user_info["email_id"],
            password=hashed_password,
            is_active=user_info["is_active"],
            created_at=datetime.datetime.now(),
            org_id=user_info["org_id"],
            first_name=user_info["first_name"],
            last_name=user_info["last_name"],
            role_id=None,
        )

        await self.user_repository.create_azure_user(new_user)
        return CreateUserResponse(user_id=new_user.id)

    async def get_user_project_permissions(self, user_id: int, permission_service) -> dict:
        """
        Returns user id, superadmin status, and for each project: project id, role id, role_type, and permissions.
        """

        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            raise exp.NotFoundError(detail="User not found")
        user_projects = await self.user_repository.get_user_reference(user_id)
        if not user_projects:
            raise exp.NotFoundError(detail="No project associations found for user")
        project_permissions = []
        async with get_db_session()() as session:
            for up in user_projects:
                role_id = up.role_id
                role_type = None
                if role_id:
                    query = select(Roles).where(Roles.id == role_id)
                    result = await session.execute(query)
                    role = result.scalar_one_or_none()
                    if role:
                        role_type = role.role_type
                permissions = []
                if role_type:
                    permissions_resp = await permission_service.list_permissions(
                        page_number=1,
                        page_size=1000,
                        search_term=None,
                        role_type_id=role_type,
                    )
                    perms = (
                        permissions_resp.permissions
                        if hasattr(permissions_resp, "permissions")
                        else []
                    )
                    permissions = [
                        {
                            "menu_item_id": getattr(p, "menu_item_id", None)
                            if not isinstance(p, dict)
                            else p.get("menu_item_id"),
                            "permission_type": getattr(p, "permission_type", None)
                            if not isinstance(p, dict)
                            else p.get("permission_type"),
                        }
                        for p in perms
                    ]
                project_permissions.append(
                    ProjectPermissionSchema(
                        project_id=up.project_id,
                        role_id=role_id,
                        role_type=role_type,
                        permissions=permissions,
                    )
                )
        return UserProjectPermissionsResponse(
            user_id=user.id,
            is_super_admin=getattr(user, "is_super_admin", False),
            projects=project_permissions,
        ).dict()

    async def get_role_type_counts_dashboard(self, project_id: int = None) -> List[dict]:
        """
        Returns the number of users for each role type.
        Super Admin is derived ONLY from users.is_super_admin.
        """
        async with get_db_session()() as session:
            # --- Super Admins (ONLY from flag) ---
            super_admin_query = select(
                literal(1).label("role_type"),
                literal("Super Admin").label("role_type_name"),
                func.count(func.distinct(UserProjectRoleAggView.user_id)).label("count"),
            ).where(UserProjectRoleAggView.is_super_admin.is_(True))

            if project_id is not None:
                super_admin_query = super_admin_query.where(
                    UserProjectRoleAggView.project_ids.contains([project_id])
                )

            super_admin_result = await session.execute(super_admin_query)
            super_admin_row = super_admin_result.first()

            # --- Other roles (explicitly exclude Super Admin role labels/types) ---
            other_roles_query = select(
                UserProjectRoleAggView.role_type,
                UserProjectRoleAggView.role_type_name,
                func.count(func.distinct(UserProjectRoleAggView.user_id)).label("count"),
            ).where(
                UserProjectRoleAggView.is_super_admin.is_(False),
                # Prevent polluted rows like admin@aiforce.com (false + role says Super Admin)
                not_(
                    and_(
                        UserProjectRoleAggView.role_type == 1,
                        UserProjectRoleAggView.role_type_name == "Super Admin",
                    )
                ),
                # (Optional extra safety) also block any "Super Admin" label regardless of type
                UserProjectRoleAggView.role_type_name != "Super Admin",
            )

            if project_id is not None:
                other_roles_query = other_roles_query.where(
                    UserProjectRoleAggView.project_ids.contains([project_id])
                )

            other_roles_query = other_roles_query.group_by(
                UserProjectRoleAggView.role_type,
                UserProjectRoleAggView.role_type_name,
            )

            other_roles_result = await session.execute(other_roles_query)
            other_roles_rows = other_roles_result.all()

            # --- Combine results (NO "sum duplicates" needed anymore) ---
            result: list[dict] = []
            if super_admin_row and super_admin_row.count and super_admin_row.count > 0:
                result.append(super_admin_row._asdict())

            result.extend([row._asdict() for row in other_roles_rows])

            return result

    async def delete_users_bulk(self, ids: list[int]) -> dict:
        """
        Deletes multiple users by their IDs.
        Args:
            ids (list[int]): List of user IDs to delete.
        Returns:
            dict: Dictionary with deleted_ids and failed_ids.
        """
        if not ids:
            return {
                "deleted_ids": [],
                "failed_ids": [],
                "message": "No user IDs provided for deletion.",
            }
        for user_id in ids:
            user_details = await self.user_repository.get_user_by_id(user_id)
            if not user_details:
                raise exp.NotFoundError(detail=f"User with id {user_id} not found")
            if user_details.user_name in ["superadmin", "admin"]:
                raise exp.BadRequestError(detail="Admin users cannot be deleted")
        return await self.user_repository.delete_users_bulk(ids)

    async def get_user_info_by_id(self) -> UserInfoResponse:
        login_user_info = get_user_info()
        result = login_user_info.__dict__
        user_data = await self.user_repository.get_user_by_id(result["user_id"])
        if user_data:
            response_data = UserInfoResponse(
                **result, first_name=user_data.first_name, last_name=user_data.last_name
            )
            return response_data
        raise exp.NotFoundError(detail=f"User with id {result['user_id']} not found")

    async def save_last_active(self):
        """
        Updates the last active timestamp for the logged-in user.
        """
        try:
            login_user_info = get_user_info()
            await self.user_repository.update_last_active(login_user_info.user_id)
            return True
        except Exception as e:
            self.logger.error(f"Error updating last active: {str(e)}")

    async def update_users_name(self, request_body) -> UpdateUserResponse:
        """
        Update only first_name and last_name for a user.
        Args:
            request_body: UpdateUserNameRequest with first_name, last_name.
        Returns:
            UpdateUserResponse: The response containing the ID of the updated user.
        Raises:
            AuthError: If the user is not found.
        """
        user_id = get_user_info().user_id
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            raise exp.AuthError(detail=msg.USER_NOT_FOUND)
        update_data = {
            "first_name": request_body.first_name,
            "last_name": request_body.last_name,
            "modified_at": datetime.datetime.now(),
        }
        await self.user_repository.update_user(user_id, update_data, None)
        return UpdateUserResponse(user_id=user_id)
