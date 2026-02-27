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

from fastapi import UploadFile, HTTPException, Depends
import aiforce_xl.exception_handler as exp
from app.services.user_service import UserService
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.project_repository import ProjectRepository
from app.models.user_projects import UserProjects
from app.schema.user_schema import InviteUserRequest
from app.schema.response_schema import BaseResponse
from datetime import datetime
import pandas as pd
from io import BytesIO
import os
from pathlib import Path
from aiforce_xl.path_handler import safe_join
import urllib.parse
from fastapi.responses import FileResponse
from app.schema.user_schema import CreateUserRequest, validate_email_format

DATA_PATH = Path(__file__).parents[4] / "services" / "aiforce-pms" / "app" / "assets" / "data"

class BulkInvitationService:
    """
    Service class for handling bulk user invitations.
    Provides methods for inviting users via CSV upload, multi-project invitations,
    downloading result files, and inviting users by JSON payload.
    """
    @staticmethod
    async def bulk_invite_user(file: UploadFile, service: UserService):
        """
        Invite users in bulk from a CSV file containing email and role information.
        Validates input, processes invitations, and returns a response with results and errors.
        """
        if not file.filename.endswith(".csv"):
            raise HTTPException(status_code=400, detail="Only .csv files are supported.")
        try:
            contents = await file.read()
            df = pd.read_csv(BytesIO(contents))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

        if len(df) > 50:
            raise exp.BadRequestError(
                detail="CSV file cannot have more than 50 rows.",
            )

        mandatory_columns = ["Email Id", "Role Name"]
        missing_cols = [col for col in mandatory_columns if col not in df.columns]
        if missing_cols:
            raise exp.BadRequestError(
                detail=f"Missing mandatory columns: {', '.join(missing_cols)}"
            )

        df_result = df.copy()
        df_result["Status"] = ""
        df_result["Remarks"] = ""

        invited = []
        errors = []

        for idx, row in df.iterrows():
            email = str(row["Email Id"]).strip() if not pd.isna(row["Email Id"]) else ""
            role_name = str(row["Role Name"]).strip() if not pd.isna(row["Role Name"]) else ""
            status = "Fail"
            remarks = ""
            if not email or not role_name:
                remarks = "Missing email or role_name"
            else:
                role_repo = RoleRepository()
                role_obj = await role_repo.get_role_by_name(role_name)
                if not role_obj:
                    remarks = "Role does not exist"
                else:
                    users = await service.user_repository.search_user(email)
                    user_obj = None
                    for u in users:
                        if u.email_id == email:
                            user_obj = u
                            break
                    if not user_obj:
                        remarks = "User does not exist"
                    else:
                        req_actual = InviteUserRequest(emails=[email], role=role_obj.id)
                        resp = await service.invite_user(req_actual)
                        if email in getattr(resp, "existing_users", []):
                            remarks = "User already invited with the same role"
                        else:
                            status = "Pass"
                            remarks = "Invited"
                            invited.append({"role": role_name, "emails": [email]})
            if status == "Fail" or remarks == "User already invited with the same role":
                errors.append({"role": role_name, "emails": [email], "error": remarks})
            df_result.at[idx, "Status"] = status if remarks == "Invited" else "Fail"
            df_result.at[idx, "Remarks"] = remarks

        result_dir = safe_join(DATA_PATH, "invite_user_result")
        os.makedirs(result_dir, exist_ok=True)
        result_filename = f"bulk_invite_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        result_path = safe_join(result_dir, result_filename + ".csv")
        df_result.to_csv(result_path, index=False)

        return BaseResponse(
            status=True if invited else False,
            message=(
                f"Bulk user invitation completed. Success: {len(invited)}, Errors: {len(errors)}. "
                f"Result file saved at {result_path}"
            ),
            data={"invited": invited, "errors": errors, "result_file": result_path},
        ).model_dump(exclude_none=True)

    @staticmethod
    async def bulk_invite_user_multi_project(file: UploadFile, service: UserService):
        """
        Invite users to multiple projects and roles from a CSV file.
        Validates input, creates users if needed, assigns roles and projects, and returns results.
        """
        if not file.filename.endswith(".csv"):
            raise HTTPException(status_code=400, detail="Only .csv files are supported.")
        try:
            contents = await file.read()
            df = pd.read_csv(BytesIO(contents))
        except Exception as e:
            raise exp.BadRequestError(detail=f"Failed to read file: {str(e)}")
        if len(df) > 50:
            raise exp.BadRequestError(detail="CSV file cannot have more than 50 rows.")

        mandatory_columns = ["Email Id", "Role Name", "Project"]
        missing_cols = [col for col in mandatory_columns if col not in df.columns]
        if missing_cols:
            raise exp.BadRequestError(
                detail=f"Missing mandatory columns: {', '.join(missing_cols)}"
            )

        df_result = df.copy()
        df_result["Status"] = ""
        df_result["Remarks"] = ""

        invited = []
        errors = []

        user_repo = UserRepository()
        role_repo = RoleRepository()
        project_repo = ProjectRepository()

        for idx, row in df.iterrows():
            email = str(row["Email Id"]).strip() if not pd.isna(row["Email Id"]) else ""
            role_name = str(row["Role Name"]).strip() if not pd.isna(row["Role Name"]) else ""
            project_name = str(row["Project"]).strip() if not pd.isna(row["Project"]) else ""
            status = "Fail"
            remarks = ""
            if not email or not role_name or not project_name:
                remarks = "Missing email, role, or project name"
            else:
                users = await user_repo.search_user(email)
                user_obj = None
                for u in users:
                    if u.email_id == email:
                        user_obj = u
                        break
                if not user_obj:
                    # Validate email format before attempting creation

                    try:
                        validate_email_format(email)
                    except Exception:
                        remarks = f"Invalid email format: {email}"
                        errors.append(
                            {
                                "role": role_name,
                                "project": project_name,
                                "emails": [email],
                                "error": remarks,
                            }
                        )
                        df_result.at[idx, "Status"] = "Fail"
                        df_result.at[idx, "Remarks"] = remarks
                        continue
                    try:
                        user_info = CreateUserRequest(
                            user_name=email,
                            email_id=email,
                            password="Welcome@1234",
                            is_active=True,
                        )
                        await service.create_user(user_info)
                        users = await user_repo.search_user(email)
                        for u in users:
                            if u.email_id == email:
                                user_obj = u
                                break
                        if not user_obj:
                            remarks = "User creation failed"
                            errors.append(
                                {
                                    "role": role_name,
                                    "project": project_name,
                                    "emails": [email],
                                    "error": remarks,
                                }
                            )
                            df_result.at[idx, "Status"] = "Fail"
                            df_result.at[idx, "Remarks"] = remarks
                            continue
                    except Exception as e:
                        remarks = f"User creation failed: {str(e)}"
                        errors.append(
                            {
                                "role": role_name,
                                "project": project_name,
                                "emails": [email],
                                "error": remarks,
                            }
                        )
                        df_result.at[idx, "Status"] = "Fail"
                        df_result.at[idx, "Remarks"] = remarks
                        continue
                project_obj = None
                if project_repo:
                    project_obj = await project_repo.get_project_by_name(project_name)
                if not project_obj:
                    remarks = "Project does not exist"
                else:
                    role_obj = await role_repo.get_role_by_name(role_name, project_obj.id)
                    if not role_obj:
                        remarks = "Role does not exist in project"
                    else:
                        user_projects = await user_repo.get_user_reference(user_obj.id)
                        in_project = None
                        for up in user_projects:
                            if up.project_id == project_obj.id:
                                in_project = up
                                break
                        if in_project:
                            if (
                                getattr(in_project, "is_invited", False)
                                and getattr(in_project, "role_id", None) == role_obj.id
                            ):
                                remarks = "User already invited with the same role in this project"
                            else:
                                await user_repo.update_user_project_role(
                                    user_obj.id, project_obj.id, role_obj.id, is_invited=True
                                )
                                status = "Pass"
                                remarks = "Invited (updated role)"
                                invited.append(
                                    {"role": role_name, "project": project_name, "emails": [email]}
                                )
                        else:
                            invited_user_project_mapping = UserProjects(
                                user_id=user_obj.id,
                                project_id=project_obj.id,
                                role_id=role_obj.id,
                                is_invited=True,
                                created_by=None,
                                created_at=datetime.now(),
                                is_default=False,
                            )
                            await user_repo.invite_user(invited_user_project_mapping)
                            status = "Pass"
                            remarks = "Invited"
                            invited.append(
                                {"role": role_name, "project": project_name, "emails": [email]}
                            )
            if status == "Fail" or "already invited" in remarks:
                errors.append(
                    {
                        "role": role_name,
                        "project": project_name,
                        "emails": [email],
                        "error": remarks,
                    }
                )
            df_result.at[idx, "Status"] = status if "Invited" in remarks else "Fail"
            df_result.at[idx, "Remarks"] = remarks

        result_dir = safe_join(DATA_PATH, "invite_user_result")
        os.makedirs(result_dir, exist_ok=True)
        result_filename = (
            f"bulk_invite_multi_project_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        result_path = safe_join(result_dir, result_filename + ".csv")
        df_result.to_csv(result_path, index=False)

        return BaseResponse(
            status=True if invited else False,
            message=(
                f"Bulk user invitation completed. Success: {len(invited)}, Errors: {len(errors)}. "
                f"Result file saved at {result_path}"
            ),
            data={"invited": invited, "errors": errors, "result_file": result_path},
        ).model_dump(exclude_none=True)

    @staticmethod
    async def download_bulk_invite_result(file: str):
        """
        Download the bulk invite result file as an attachment.
        Returns a FileResponse for the requested CSV result file.
        Raises HTTPException if the file is not found.
        """
        result_dir = safe_join(DATA_PATH, "invite_user_result")

        safe_file = os.path.basename(file)
        file_path = safe_join(result_dir, safe_file)
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Result file not found.")
        if file_path.endswith(".csv"):
            media_type = "text/csv"
        else:
            media_type = "application/octet-stream"
        return FileResponse(
            file_path,
            media_type=media_type,
            filename=safe_file,
            headers={
                "Content-Disposition": (
                    f"attachment; filename*=UTF-8''"
                    f"{urllib.parse.quote(safe_file)}"
                )
            },
        )

    @staticmethod
    async def bulk_invite_user_by_payload(payload, service: UserService):
        """
        Invite users to multiple projects/roles as per JSON payload:
        {
            "emails": ["user1@hcl.com", ...],
            "projects": [
                {"project_name": "Project1", "role_name": "RoleA"},
                ...
            ]
        }
        """
        user_repo = UserRepository()
        role_repo = RoleRepository()
        project_repo = ProjectRepository()
        emails = payload.emails
        projects = payload.projects
        invited = []
        errors = []
        for project in projects:
            project_name = project.project_name
            role_name = project.role_name
            project_obj = await project_repo.get_project_by_name(project_name)
            if not project_obj:
                for email in emails:
                    errors.append(
                        {
                            "project": project_name,
                            "role": role_name,
                            "emails": [email],
                            "error": "Project does not exist",
                        }
                    )
                continue
            role_obj = await role_repo.get_role_by_name(role_name, project_obj.id)
            if not role_obj:
                for email in emails:
                    errors.append(
                        {
                            "project": project_name,
                            "role": role_name,
                            "emails": [email],
                            "error": "Role does not exist in project",
                        }
                    )
                continue
            for email in emails:
                users = await user_repo.search_user(email)
                user_obj = None
                for u in users:
                    if u.email_id == email:
                        user_obj = u
                        break
                if not user_obj:
                    errors.append(
                        {
                            "project": project_name,
                            "role": role_name,
                            "emails": [email],
                            "error": "User does not exist",
                        }
                    )
                    continue
                user_projects = await user_repo.get_user_reference(user_obj.id)
                in_project = None
                for up in user_projects:
                    if up.project_id == project_obj.id:
                        in_project = up
                        break
                if in_project:
                    if (
                        getattr(in_project, "is_invited", False)
                        and getattr(in_project, "role_id", None) == role_obj.id
                    ):
                        errors.append(
                            {
                                "project": project_name,
                                "role": role_name,
                                "emails": [email],
                                "error": "User already invited with the same role in this project",
                            }
                        )
                        continue
                    else:
                        await user_repo.update_user_project_role(
                            user_obj.id, project_obj.id, role_obj.id, is_invited=True
                        )
                        invited.append(
                            {"project": project_name, "role": role_name, "emails": [email]}
                        )
                else:
                    invited_user_project_mapping = UserProjects(
                        user_id=user_obj.id,
                        project_id=project_obj.id,
                        role_id=role_obj.id,
                        is_invited=True,
                        created_by=None,
                        created_at=datetime.now(),
                        is_default=False,
                    )
                    await user_repo.invite_user(invited_user_project_mapping)
                    invited.append({"project": project_name, "role": role_name, "emails": [email]})
        return BaseResponse(
            status=True if invited else False,
            message=(
                f"Bulk user invitation completed. Success: {len(invited)}, "
                f"Errors: {len(errors)}."
            ),
            data={"invited": invited, "errors": errors},
        ).model_dump(exclude_none=True)
