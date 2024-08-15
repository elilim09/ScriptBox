from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# 사용자 생성 스키마
class UserCreateSchema(BaseModel):
    nickname: str
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    def validate_passwords(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")

# 데이터베이스에서의 사용자 스키마
class UserInDBSchema(BaseModel):
    id: int
    nickname: str
    username: str
    email: EmailStr
    created_at: datetime
    admin: bool

    class Config:
        orm_mode = True 
class UserInDBSchema(UserCreateSchema):
    admin: int
class QboardPostBaseSchema(BaseModel):
    title: str
    content: str
    nickname: str
    file_url: Optional[str] = None 

class QboardPostCreateSchema(QboardPostBaseSchema):
    pass

class QboardPostSchema(QboardPostBaseSchema):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

class QboardCommentBaseSchema(BaseModel):
    content: str
    nickname: str

class QboardCommentCreateSchema(QboardCommentBaseSchema):
    post_id: int

class QboardCommentSchema(QboardCommentBaseSchema):
    id: int

    class Config:
        orm_mode = True

class QboardPostDetailSchema(QboardPostSchema):
    comments: List[QboardCommentSchema] = []

class ShareboxPostBaseSchema(BaseModel):
    title: str
    content: str
    nickname: str
    file_url: Optional[str] = None 

class ShareboxPostCreateSchema(ShareboxPostBaseSchema):
    pass

class ShareboxPostSchema(ShareboxPostBaseSchema):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True

class ShareboxCommentBaseSchema(BaseModel):
    content: str
    nickname: str

class ShareboxCommentCreateSchema(ShareboxCommentBaseSchema):
    post_id: int

class ShareboxCommentSchema(ShareboxCommentBaseSchema):
    id: int

    class Config:
        orm_mode = True

class ShareboxPostDetailSchema(ShareboxPostSchema):
    comments: List[ShareboxCommentSchema] = []
