package model

import (
//"time"
//"gopkg.in/mgo.v2/bson"
)

//userInfo
type User struct {
	FirstName        string `json:"first_name" valid:"required"`
	LastName         string `json:"last_name" valid:"required"`
	UserName         string `json:"user_name" valid:"required"`
	Email            string `json:"email"  valid:"required"`
	MobileNo         int64  `json:"mobile_no"  valid:"required"`
	Password         string `json:"password" valid:"required"`
	IsActive         int    `json:"is_active" `
	JWT              string `json:"jwt"`
	IsJWTActive      int    `json:"is_jwt_active"`
	ValidUpto        string `json:"validUpto"`
	VerificationCode int    `json:"verificationCode"`
}

//LoginInfo
type LoginInfo struct {
	ID       string `bson:"_id,omitempty"`
	UserName string `json:"user_name" valid:"required"`
	Password string `json:"password" valid:"required"`
}

//ChangePassword
type ChangePassword struct {
	Email       string `json:"email"  valid:"required"`
	Password    string `json:"password" valid:"required"`
	NewPassword string `json:"new_password" valid:"required"`
	JWT         string `json:"jwt" valid:"required"`
}

//ForgotPassword
type ForgotPassword struct {
	Email string `json:"email"  valid:"required"`
}

//VerifyCode
type VerifyCode struct {
	Email string `json:"email"  valid:"required"`
	Code  int    `json:"code" valid:"required"`
}
