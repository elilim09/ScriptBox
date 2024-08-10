from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi.templating import Jinja2Templates
from models import Base, UserModel, QboardPostModel, QboardCommentModel, LikeModel  # 모델을 가져옵니다
from schemas import UserCreateSchema, UserInDBSchema, QboardPostSchema, QboardCommentSchema, QboardPostDetailSchema
from fastapi.responses import RedirectResponse
from fastapi.responses import JSONResponse
from fastapi import File, UploadFile
import dropbox
from sqlalchemy.orm import aliased
from dropbox.files import WriteMode
ACCESS_TOKEN = 'sl.B6n5FnDqe92aq-KS2BKo7Fw0LWVUjBXXrQ2HX70BdpiqQUHGV3qHA_UuVwi97k7XdT46p6fTVSzurc4thGFM4bP5YjCI5c_X8Yrs6W0tGXNa9hiAOHCsvVRi_4m5J2aAvIeQ_HdeWUm-OsI'
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# 데이터베이스 설정
SQLALCHEMY_DATABASE_URL = "mysql://root:qwaszx77^^@svc.sel4.cloudtype.app:31994/hackton"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 설정
SECRET_KEY = "my_fixed_secret_key"  # 고정된 비밀 키
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI 앱 및 Jinja2Templates 설정
app = FastAPI()
templates = Jinja2Templates(directory="public")

# 데이터베이스 세션 의존성
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def toggle_like(db: Session, post_id: int, user_id: int):
    like = db.query(models.LikeModel).filter_by(post_id=post_id, user_id=user_id).first()
    if like:
        db.delete(like)
    else:
        new_like = models.LikeModel(user_id=user_id, post_id=post_id)
        db.add(new_like)
    db.commit()
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
@app.get("/index")
async def home(request: Request, db: Session = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    user_info = None

    if access_token:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user_info = {
                "nickname": payload.get("nickname"),
                "email": payload.get("sub"),
                "admin": payload.get("admin")
            }
        except JWTError:
            pass

    # Subquery to count likes per post
    like_subquery = db.query(
        LikeModel.post_id,
        func.count(LikeModel.post_id).label("like_count")
    ).group_by(LikeModel.post_id).subquery()

    # Aliased models
    post_alias = aliased(QboardPostModel)
    like_alias = aliased(like_subquery)

    # Query to get top 3 posts with most likes
    top_posts_query = db.query(
        post_alias,
        like_alias.c.like_count
    ).outerjoin(
        like_alias, post_alias.id == like_alias.c.post_id
    ).order_by(
        like_alias.c.like_count.desc()
    ).limit(3)

    top_posts = top_posts_query.all()

    return templates.TemplateResponse("index.html", {"request": request, "user_info": user_info, "top_posts": top_posts})


@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register")
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/post/register")
async def register_user(
    nickname: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # 사용자 등록 데이터 검증
    user_data = UserCreateSchema(
        nickname=nickname,
        username=username,
        email=email,
        password=password,
        confirm_password=confirm_password
    )

    # 비밀번호 검증
    try:
        user_data.validate_passwords()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 중복된 사용자 확인
    existing_user_nickname = db.query(UserModel).filter(UserModel.nickname == user_data.nickname).first()
    if existing_user_nickname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nickname already registered")

    existing_user_email = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # 사용자 생성
    hashed_password = get_password_hash(user_data.password)
    db_user = UserModel(
        nickname=user_data.nickname,
        username=user_data.username,
        email=user_data.email,
        password=hashed_password
    )

    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    return templates.TemplateResponse("login.html", {"request": request, "user_info": user_info})
    
@app.post("/post/login")
async def login_user(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter(
        (UserModel.email == form_data.username) | (UserModel.nickname == form_data.username)
    ).first()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user.email,
            "nickname": user.nickname,
            "admin": user.admin  # admin 정보를 추가합니다.
        },
        expires_delta=access_token_expires
    )
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=access_token_expires,
        expires=access_token_expires,
        secure=True,  # HTTPS가 아닌 경우 False로 설정
        samesite="Strict"  # 필요에 따라 조정
    )

    return {"msg": "Login successful"}
@app.post("/post/logout")
async def logout(response: Response):
    # Clear the access token cookie
    response.delete_cookie("access_token")
    return {"msg": "Logout successful"}

@app.get("/qbox_create")
def qbox_create(request: Request):
    return templates.TemplateResponse("qbox_create.html", {"request": request})

@app.get("/qbox")
async def qbox(request: Request, db: Session = Depends(get_db)):
    # 로그인 상태 확인
    access_token = request.cookies.get("access_token")
    user_info = None

    if access_token:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user_info = {"nickname": payload.get("nickname"), "email": payload.get("sub")}
        except JWTError:
            pass

    # 게시물 조회
    posts = db.query(QboardPostModel).order_by(QboardPostModel.created_at.desc()).all()

    return templates.TemplateResponse("Qbox.html", {"request": request, "posts": posts, "user_info": user_info})
@app.post("/post/create_qbox")
async def create_qbox_post(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
    file: UploadFile = File(None),  # File is optional
    db: Session = Depends(get_db)
):
    # Check for authentication
    access_token = request.cookies.get("access_token")
    if access_token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        nickname = payload.get("nickname")
        if nickname is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    # Create a new post
    db_post = QboardPostModel(title=title, content=content, nickname=nickname, file_url=None)
    try:
        db.add(db_post)
        db.commit()
        db.refresh(db_post)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database integrity error")

    # Handle file upload if provided
    if file and file.filename:
        file_content = await file.read()
        if len(file_content) == 0:
            return {"msg": "File was empty, post created without file"}
        
        try:
            # Define folder path in Dropbox
            folder_path = f'/{nickname}-{db_post.id}'

            # Create folder if it doesn't exist
            try:
                dbx.files_get_metadata(folder_path)
            except dropbox.exceptions.ApiError as e:
                if e.error.is_path() and e.error.get_path().is_not_found():
                    dbx.files_create_folder_v2(folder_path)
                else:
                    raise HTTPException(status_code=500, detail=f"Failed to check or create folder: {str(e)}")

            # Define file path and upload to Dropbox
            file_path = f'{folder_path}/{file.filename}'
            dbx.files_upload(file_content, file_path, mode=WriteMode("overwrite"))
            
            # Create a shared link for the uploaded file
            link_response = dbx.sharing_create_shared_link_with_settings(file_path)
            shared_link = link_response.url
            
            # Update post with file URL
            db_post.file_url = shared_link
            db.add(db_post)
            db.commit()
            db.refresh(db_post)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

    return RedirectResponse(url="/qbox", status_code=303)
@app.get("/viewqbox/{post_id}")
async def view_qbox(post_id: int, request: Request, db: Session = Depends(get_db)):
    # 로그인 상태 확인
    access_token = request.cookies.get("access_token")
    user_info = None
    post_user_liked = False
    is_admin = False

    if access_token:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user_info = {"nickname": payload.get("nickname"), "email": payload.get("sub")}
            # 사용자가 이 게시물에 좋아요를 눌렀는지 확인
            user = db.query(UserModel).filter(UserModel.email == payload.get("sub")).first()
            if user:
                post_user_liked = db.query(LikeModel).filter(LikeModel.post_id == post_id, LikeModel.user_id == user.id).first() is not None
                # 사용자 정보에서 admin 여부 확인
                is_admin = user.admin if user else False
        except JWTError:
            pass

    # 게시물 조회
    post = db.query(QboardPostModel).filter(QboardPostModel.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # 댓글 조회
    comments = db.query(QboardCommentModel).filter(QboardCommentModel.post_id == post_id).all()
    
    # 게시물의 좋아요 수 계산
    like_count = db.query(func.count(LikeModel.post_id)).filter(LikeModel.post_id == post_id).scalar() or 0

    # Add file_url to the post object
    file_url = post.file_url if post.file_url else None
    print(file_url)
    return templates.TemplateResponse("view_qbox.html", {
        "request": request,
        "post": post,
        "comments": comments,
        "user_info": user_info,
        "post_id": post_id,
        "like_count": like_count,
        "post_user_liked": post_user_liked,
        "is_admin": is_admin,
        "file_url": file_url
    })

@app.post("/post/comment")
async def create_comment(
    request: Request,
    post_id: int = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db)
):
    # 쿠키에서 액세스 토큰 가져오기
    access_token = request.cookies.get("access_token")
    if access_token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # 토큰 검증 및 닉네임 추출
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        nickname = payload.get("nickname")
        if nickname is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    # 게시물 확인
    post = db.query(QboardPostModel).filter(QboardPostModel.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # 댓글 생성
    db_comment = QboardCommentModel(content=content, nickname=nickname, post_id=post_id)
    try:
        db.add(db_comment)
        db.commit()
        db.refresh(db_comment)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    # 게시물 상세 페이지로 리디렉션
    return RedirectResponse(url=f"/viewqbox/{post_id}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/post/{post_id}/like")
async def like_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="로그인 후 사용해주세요.")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="로그인 후 사용해주세요.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 토큰입니다.")

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 사용자입니다.")

    like = db.query(LikeModel).filter(LikeModel.post_id == post_id, LikeModel.user_id == user.id).first()
    
    if like:
        db.delete(like)
        db.commit()
        message = "Like removed"
        status = "success"
    else:
        new_like = LikeModel(post_id=post_id, user_id=user.id)
        db.add(new_like)
        db.commit()
        message = "Like added"
        status = "success"

    # Calculate the new like count
    like_count = db.query(func.count(LikeModel.post_id)).filter(LikeModel.post_id == post_id).scalar() or 0

    return {"status": status, "message": message, "like_count": like_count}
@app.get("/post/edit/{post_id}")
async def edit_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    user_info = None

    if access_token:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user_info = {"nickname": payload.get("nickname"), "email": payload.get("sub"), "admin": payload.get("admin")}
        except JWTError:
            pass

    post = db.query(QboardPostModel).filter(QboardPostModel.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    if not (user_info and (user_info["nickname"] == post.nickname or user_info["admin"] == 1)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to edit this post")

    return templates.TemplateResponse("edit_post.html", {"request": request, "post": post})

@app.post("/post/edit/{post_id}")
async def update_post(
    request: Request,
    post_id: int,
    title: str = Form(...),
    content: str = Form(...),
    file: UploadFile = File(None),  # File is optional
    db: Session = Depends(get_db)
):
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        nickname = payload.get("nickname")
        admin = payload.get("admin", 0)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    post = db.query(QboardPostModel).filter(QboardPostModel.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    if not (nickname == post.nickname or admin == 1):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to edit this post")

    # Handle file upload if provided
    if file and file.filename:
        file_content = await file.read()
        try:
            # Upload file to Dropbox
            response = dbx.files_upload(file_content, f'/{post_id}/{file.filename}', mode=WriteMode("overwrite"))
            file_url = response.path_display  # Update the file URL
            # Create a shared link for the uploaded file
            link_response = dbx.sharing_create_shared_link_with_settings(file_url)
            shared_link = link_response.url
            post.file_url = shared_link
        except Exception as e:
            raise HTTPException(status_code=500, detail="File upload failed: " + str(e))
    
    post.title = title
    post.content = content
    db.commit()

    return RedirectResponse(url=f"/viewqbox/{post_id}", status_code=status.HTTP_303_SEE_OTHER)



@app.post("/post/delete/{post_id}")
def delete_post(post_id: int, db: Session = Depends(get_db)):
    # Delete comments associated with the post
    db.query(QboardCommentModel).filter(QboardCommentModel.post_id == post_id).delete(synchronize_session=False)
    
    # Delete the post
    post = db.query(QboardPostModel).filter(QboardPostModel.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    
    db.delete(post)
    db.commit()
    
    return templates.TemplateResponse("Qbox.html", {"request": request})
@app.post("/comment/delete/{comment_id}")
async def delete_comment(comment_id: int, request: Request, db: Session = Depends(get_db)):
    # 로그인 상태 확인
    access_token = request.cookies.get("access_token")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        user = db.query(UserModel).filter(UserModel.email == user_email).first()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
        comment = db.query(QboardCommentModel).filter(QboardCommentModel.id == comment_id).first()
        
        if not comment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Comment not found")
        
        if comment.id != user.id and not user.admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this comment")
        
        db.delete(comment)
        db.commit()
        return {"message": "Comment deleted successfully"}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
@app.get("/admin")
async def get_all_users(request: Request, db: Session = Depends(get_db)):
    # Check if the user is authenticated
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        is_admin = payload.get("admin") == 1
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Fetch all users, excluding passwords
    users = db.query(UserModel).all()
    user_list = [
        {
            "id": user.id,
            "nickname": user.nickname,
            "username": user.username,
            "email": user.email,
            "admin": user.admin
        }
        for user in users
    ]

    return templates.TemplateResponse("admin.html", {"request": request, "users": user_list})

@app.post("/admin/reset_password")
async def reset_password(
    request: Request,
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if the user is an admin
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        is_admin = payload.get("admin") == 1
        if not is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Find the user
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Reset the user's password
    hashed_password = get_password_hash("1234")  # Default password
    user.password = hashed_password

    try:
        db.add(user)
        db.commit()
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database integrity error")

    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/admin/set_admin/{user_id}")
async def set_admin(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.admin = 1
    db.commit()
    
    return RedirectResponse(url="/admin", status_code=302)

@app.get("/mypage")
async def mypage(request: Request, db: Session = Depends(get_db)):
    access_token = request.cookies.get("access_token")
    
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        
        if not user_email:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        
        user = db.query(UserModel).filter(UserModel.email == user_email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
    
    return templates.TemplateResponse("mypage.html", {"request": request, "user": user})

@app.post("/mypage/update_profile")
async def update_profile(
    request: Request,
    nickname: str = Form(...),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
    
    db: Session = Depends(get_db)
):
    # 현재 로그인한 사용자의 정보 가져오기
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    current_user = get_current_user(db, access_token)
    

    # 비밀번호 확인
    if not verify_password(current_password, current_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

    # 새 비밀번호 확인
    if new_password != confirm_new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match")

    # 비밀번호 해싱 및 업데이트
    hashed_new_password = get_password_hash(new_password)
    current_user.nickname = nickname
    current_user.password = hashed_new_password

    try:
        db.add(current_user)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update profile")

    return RedirectResponse(url="/mypage", status_code=status.HTTP_302_FOUND)


# 비밀번호 해시 함수 예제 (실제 구현 시 보안 강화 필요)
def hash_password(password: str) -> str:
    # 실제 비밀번호 해싱 알고리즘을 사용해야 합니다.
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user(db: Session, access_token: str) -> UserModel:
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")
        user = db.query(UserModel).filter(UserModel.email == email).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")