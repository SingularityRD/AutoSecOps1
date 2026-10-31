"""Email verification routes for password accounts.

Replaces fastapi-users' verify router, whose ``POST /verify`` marks an account
verified from the token alone. Here the emailed link also sets the password
(see ``UserManager.verify_with_password``), so whoever proves the mailbox owns
the account. Route names match fastapi-users' so rate limits attach by name.
"""

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi_users import InvalidPasswordException
from fastapi_users.exceptions import (
    InvalidVerifyToken,
    UserAlreadyVerified,
    UserInactive,
    UserNotExists,
)
from fastapi_users.router.common import ErrorCode, ErrorModel
from pydantic import EmailStr

from autosecops.auth.schemas import UserRead
from autosecops.auth.users import UserManager, get_user_manager

VERIFY_USER_INVALID_PASSWORD = "VERIFY_USER_INVALID_PASSWORD"
"""Error code for a verification whose new password fails the policy."""


def get_verify_router() -> APIRouter:
    """Build the ``/request-verify-token`` and ``/verify`` routes."""
    router = APIRouter()

    @router.post(
        "/request-verify-token",
        status_code=status.HTTP_202_ACCEPTED,
        name="verify:request-token",
    )
    async def request_verify_token(  # pyright: ignore[reportUnusedFunction] - registered as FastAPI route handler
        request: Request,
        email: EmailStr = Body(..., embed=True),
        user_manager: UserManager = Depends(get_user_manager),
    ) -> None:
        # The answer is the same whether or not the account exists.
        try:
            user = await user_manager.get_by_email(email)
            await user_manager.request_verify(user, request)
        except (UserNotExists, UserInactive, UserAlreadyVerified):
            pass

    @router.post(
        "/verify",
        response_model=UserRead,
        name="verify:verify",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            ErrorCode.VERIFY_USER_BAD_TOKEN: {
                                "summary": "Bad token, not existing user or"
                                " not the e-mail currently set for the user.",
                                "value": {"detail": ErrorCode.VERIFY_USER_BAD_TOKEN},
                            },
                            ErrorCode.VERIFY_USER_ALREADY_VERIFIED: {
                                "summary": "The user is already verified.",
                                "value": {
                                    "detail": ErrorCode.VERIFY_USER_ALREADY_VERIFIED
                                },
                            },
                            VERIFY_USER_INVALID_PASSWORD: {
                                "summary": "Password validation failed.",
                                "value": {
                                    "detail": {
                                        "code": VERIFY_USER_INVALID_PASSWORD,
                                        "reason": "Password should be at least "
                                        "12 characters",
                                    }
                                },
                            },
                        }
                    }
                },
            }
        },
    )
    async def verify(  # pyright: ignore[reportUnusedFunction] - registered as FastAPI route handler
        request: Request,
        token: str = Body(..., embed=True),
        password: str = Body(..., embed=True),
        user_manager: UserManager = Depends(get_user_manager),
    ) -> UserRead:
        try:
            user = await user_manager.verify_with_password(token, password, request)
        except InvalidVerifyToken:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_BAD_TOKEN,
            ) from None
        except UserAlreadyVerified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ErrorCode.VERIFY_USER_ALREADY_VERIFIED,
            ) from None
        except InvalidPasswordException as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": VERIFY_USER_INVALID_PASSWORD, "reason": e.reason},
            ) from None
        return UserRead.model_validate(user)

    return router
