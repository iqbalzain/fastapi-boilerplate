"""Authentication endpoints.

Access tokens travel in the JSON body (stored in memory by SPAs). Refresh tokens
are set as an ``HttpOnly`` cookie scoped to the auth path so JavaScript cannot
read them and they are not sent with ordinary API calls. Over HTTPS the cookie
carries the ``__Secure-`` prefix (``__Host-`` would forbid the path scoping).
"""

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentUser, DbSession, DenylistDep, RateLimit, SettingsDep
from app.core.config import Settings
from app.core.exceptions import UnauthorizedError
from app.core.security import new_csrf_token
from app.modules.auth.schemas import CsrfResponse, LoginRequest, TokenResponse
from app.modules.auth.service import AuthService, TokenPair
from app.modules.users.service import UserService

router = APIRouter(prefix="/auth", tags=["auth"])


def _refresh_cookie_path(settings: Settings) -> str:
    return f"{settings.api_prefix}/auth"


def _set_refresh_cookie(response: Response, settings: Settings, pair: TokenPair) -> None:
    response.set_cookie(
        key=settings.effective_refresh_cookie_name,
        value=pair.refresh.token,
        max_age=settings.refresh_token_ttl_seconds,
        path=_refresh_cookie_path(settings),
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.effective_refresh_cookie_name,
        path=_refresh_cookie_path(settings),
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _token_response(settings: Settings, pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access.token, expires_in=settings.access_token_ttl_seconds
    )


@router.get("/csrf", response_model=CsrfResponse, summary="Obtain a CSRF token")
async def csrf(response: Response, settings: SettingsDep) -> CsrfResponse:
    token = new_csrf_token(settings)
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=token,
        path="/",
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=False,  # JS must read it to echo it in the header
        samesite=settings.cookie_samesite,
    )
    return CsrfResponse(csrf_token=token)


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(RateLimit(5, 60, scope="login"))],
    summary="Exchange credentials for tokens",
)
async def login(
    data: LoginRequest,
    response: Response,
    session: DbSession,
    settings: SettingsDep,
    denylist: DenylistDep,
) -> TokenResponse:
    user = await UserService(session).authenticate(data.email, data.password)
    if user is None:
        # Identical message for unknown email and wrong password.
        raise UnauthorizedError("Invalid credentials.")
    pair = AuthService(settings, denylist).issue_pair(str(user.id))
    _set_refresh_cookie(response, settings, pair)
    return _token_response(settings, pair)


@router.post("/refresh", response_model=TokenResponse, summary="Rotate the refresh token")
async def refresh(
    request: Request, response: Response, settings: SettingsDep, denylist: DenylistDep
) -> TokenResponse:
    token = request.cookies.get(settings.effective_refresh_cookie_name)
    if not token:
        raise UnauthorizedError("Missing refresh token.")
    pair = await AuthService(settings, denylist).rotate(token)
    _set_refresh_cookie(response, settings, pair)
    return _token_response(settings, pair)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke tokens")
async def logout(
    request: Request,
    response: Response,
    user: CurrentUser,
    settings: SettingsDep,
    denylist: DenylistDep,
) -> Response:
    service = AuthService(settings, denylist)
    await service.revoke_access(request.state.access_jti, request.state.access_exp)
    await service.revoke_refresh(request.cookies.get(settings.effective_refresh_cookie_name))
    _clear_refresh_cookie(response, settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
