package service

import (
	//"fmt"
	"github.com/rightjoin/aqua"
	"user/api/util"
)

type User struct {
	aqua.RestService `prefix:"user/" root:"/" version:"1"`
	signUp           aqua.POST `url:"/get"`
	login            aqua.POST `url:"/login"`
	details          aqua.GET  `url:"/details"`
	forgotPassword   aqua.POST `url:"/forgotPassword"`
	verifyCode       aqua.POST `url:"/verifyCode"`
	changePassword   aqua.POST `url:"/changePassword"`
	signOut          aqua.GET  `url:"/signOut"`
}

//user SignUp
func (usr *User) SignUp(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.SignUp(j)
	return
}

//user Login
func (usr *User) Login(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.Login(j)
	return
}

//user Details
func (usr *User) Details(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.Details(j)
	return
}

//user ForgotPassword
func (usr *User) ForgotPassword(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.ForgotPassword(j)
	return

}

//user VerifyCode
func (usr *User) VerifyCode(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.VerifyCode(j)
	return
}

//user  ChangePassword
func (usr *User) ChangePassword(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.ChangePassword(j)
	return
}

// user SignOut
func (usr *User) SignOut(j aqua.Aide) (
	response interface{}, err error) {
	response, err = util.SignOut(j)
	return
}
