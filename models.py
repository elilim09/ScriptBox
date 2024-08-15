from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

Base = declarative_base()

class UserModel(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    nickname = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    admin = Column(Integer, default=0)
class QboardPostModel(Base):
    __tablename__ = 'qbox_posts'
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    nickname = Column(String, nullable=False)
    file_url = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    
    comments = relationship("QboardCommentModel", back_populates="post", cascade="all, delete-orphan")

class QboardCommentModel(Base):
    __tablename__ = 'qbox_comments'
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    nickname = Column(String, nullable=False)
    post_id = Column(Integer, ForeignKey('qbox_posts.id'), index=True)
    
    post = relationship("QboardPostModel", back_populates="comments")

class LikeModel(Base):
    __tablename__ = 'likes'
    
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    post_id = Column(Integer, ForeignKey('qbox_posts.id', ondelete='CASCADE'), primary_key=True)
    
    __table_args__ = (
        UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),
    )
class ShareboxPostModel(Base):
    __tablename__ = 'sharebox_posts'
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    nickname = Column(String, nullable=False)
    file_url = Column(String, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    
    comments = relationship("ShareboxCommentModel", back_populates="post", cascade="all, delete-orphan")

class ShareboxCommentModel(Base):
    __tablename__ = 'sharebox_comments'
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    nickname = Column(String, nullable=False)
    post_id = Column(Integer, ForeignKey('sharebox_posts.id'), index=True)
    
    post = relationship("ShareboxPostModel", back_populates="comments")

class ShareboxLikeModel(Base):
    __tablename__ = 'sharebox_likes'
    
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    post_id = Column(Integer, ForeignKey('sharebox_posts.id', ondelete='CASCADE'), primary_key=True)
    
    __table_args__ = (
        UniqueConstraint('user_id', 'post_id', name='unique_user_sharebox_like'),
    )
