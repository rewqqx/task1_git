from fastapi.security import OAuth2PasswordRequestForm

from src.models.schemas.utils.jwt_token import JwtToken

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from src.models.schemas.user.user_request import UserRequest
from src.models.schemas.user.user_response import UserResponse
from src.services.users import UsersService
from src.services.users import get_current_user_id, check_admin

router = APIRouter(
    prefix='/users',
    tags=['users'],
)


@router.post('/register', status_code=status.HTTP_201_CREATED, name='Регистрация')
def register(user_schema: UserRequest, user_service: UsersService = Depends()):
    """
    Регистрация
    """
    return user_service.register(user_schema)


@router.post('/authorize', response_model=JwtToken, name='Авторизация')
def authorize(auth_schema: OAuth2PasswordRequestForm = Depends(), users_service: UsersService = Depends()):
    """
    Авторизация
    """
    result = users_service.authorize(auth_schema.username, auth_schema.password)
    if not result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Не авторизован')
    return result


@router.get('/all', response_model=List[UserResponse], name='Получить всех пользователей')
def get(users_service: UsersService = Depends(), user_id: int = Depends(get_current_user_id), user_req: int = Depends(check_admin)):
    """
    Получить всех пользователей
    """
    print(user_id)
    return users_service.all()

