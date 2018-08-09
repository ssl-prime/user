package util

import (
	"encoding/json"
	"fmt"
	"github.com/asaskevich/govalidator"
	"github.com/dgrijalva/jwt-go"
	"github.com/rightjoin/aqua"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
	"user/api/model"
)

//SignUp
func SignUp(j aqua.Aide) (response interface{}, err error) {

	j.LoadVars()
	var reqPayload model.User
	if err = json.Unmarshal([]byte(j.Body), &reqPayload); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayload); err == nil {
			if session, err := mgo.Dial("localhost"); err == nil {
				//bcrypt password
				if password, err := BcryptPassword(reqPayload.Password); err == nil {
					c := session.DB("cubereum").C("nitp").Insert(bson.M{
						"first_name": reqPayload.FirstName,
						"last_name":  reqPayload.LastName,
						"user_name":  reqPayload.UserName,
						"email":      reqPayload.Email,
						"mobile_no":  reqPayload.MobileNo,
						"password":   password,
						"is_active":  1,
						"created_at": time.Now(),
						"updated_at": time.Now()})
					fmt.Println(c)
				} else {
					fmt.Println(err, "bcrypt")
				}

			} else {
				fmt.Println(err, "  connection")
			}
		}
	}

	return "connected checkup", err
}

//Login
func Login(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	var (
		reqPayload model.LoginInfo
		jwtStr     string
	)
	if err = json.Unmarshal([]byte(j.Body), &reqPayload); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayload); err == nil {
			if session, err := mgo.Dial("localhost"); err == nil {
				result := model.LoginInfo{}
				if err = session.DB("cubereum").C("nitp").Find(bson.M{
					"user_name": reqPayload.UserName,
					"password":  reqPayload.Password}).One(&result); err == nil {
					if CheckPasswordHash(reqPayload.Password, result.Password) {
						fmt.Println("matched")
						if jwtStr, err = GenerateJWTToken("123456"); err == nil {
							session.DB("cubereum").C("nitp").Upsert(
								bson.M{"user_name": result.UserName},
								bson.M{"$set": bson.M{"jwt": jwtStr, "is_jwt_active": 1,
									"validUpto":  10 * time.Now().Unix(),
									"updated_at": time.Now().Unix()}},
							)
						}
						fmt.Println(jwtStr, "token")
					}
					fmt.Println(result, err)
				}
			}
		}
	}

	return jwtStr, err
}

//Details
func Details(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	header := j.Request.Header
	result := model.User{}
	fmt.Println(header.Get("jwt"))
	if header.Get("jwt") != `` {
		if session, err := mgo.Dial("localhost"); err == nil {
			err = session.DB("cubereum").C("nitp").Find(
				bson.M{"jwt": header.Get("jwt")}).One(&result)
			fmt.Println(result, err)
		}
	}

	return result, nil
}

//ForgotPassword
func ForgotPassword(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	var (
		reqPayload model.ForgotPassword
	)
	if err = json.Unmarshal([]byte(j.Body), &reqPayload); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayload); err == nil {
			if session, err := mgo.Dial("localhost"); err == nil {
				count := 0
				fmt.Println("forgot")
				if count, err = session.DB("cubereum").C("nitp").
					Find(bson.M{"email": reqPayload.Email}).Count(); err == nil {
					if count == 1 {
						//todo
						//we have to generate vrification code and send it to given email
						//insert into collection
						fmt.Println("send verification code")
					}
				}
			}
		}
	}
	return reqPayload.Email, err
}

//VerifyCode
func VerifyCode(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	var (
		reqPayload model.VerifyCode
		result     model.VerifyCode
		jwtStr     string
	)
	if err = json.Unmarshal([]byte(j.Body), &reqPayload); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayload); err == nil {
			if session, err := mgo.Dial("localhost"); err == nil {
				fmt.Println("verifyCode")
				if err = session.DB("cubereum").C("nitp").
					Find(bson.M{"email": reqPayload.Email}).One(&result); err == nil {
					if result.Code == reqPayload.Code {
						fmt.Println("generate JWTToken")
						jwtStr, err = GenerateJWTToken("123456")

					} else {
						fmt.Println("not found")
					}
				}
			}
		}
	}
	return jwtStr, err
}

//ChangePassword
func ChangePassword(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	var (
		reqPayload model.ChangePassword
		result     model.LoginInfo
		//jwtStr,
		password string
		change   *mgo.ChangeInfo
	)

	if err = json.Unmarshal([]byte(j.Body), &reqPayload); err == nil {
		if _, err = govalidator.ValidateStruct(reqPayload); err == nil {
			if session, err := mgo.Dial("localhost"); err == nil {
				fmt.Println("changePassword")
				if err = session.DB("cubereum").C("nitp").
					Find(bson.M{"email": reqPayload.Email, "jwt": reqPayload.JWT,
						"is_jwt_active": 1, "is_active": 1}).One(&result); err == nil {
					if CheckPasswordHash(reqPayload.Password, result.Password) {
						password, err = BcryptPassword(reqPayload.NewPassword)
						change, err = session.DB("cubereum").C("nitp").Upsert(
							bson.M{"user_name": result.UserName},
							bson.M{"$set": bson.M{"password": password,
								"updated_at": time.Now().Unix()}},
						)
						fmt.Println("generate JWTToken")
						//jwtStr, err = GenerateJWTToken("123456")

					} else {
						fmt.Println("not found")
					}
				}
			}
		}
	}
	return change, err
}

//SignOut
func SignOut(j aqua.Aide) (response interface{}, err error) {
	j.LoadVars()
	header := j.Request.Header
	var change *mgo.ChangeInfo
	fmt.Println(header.Get("jwt"))
	if header.Get("jwt") != `` {
		if session, err := mgo.Dial("localhost"); err == nil {
			change, err = session.DB("cubereum").C("nitp").Upsert(
				bson.M{"jwt": header.Get("jwt")},
				bson.M{"$set": bson.M{"is_jwt_active": 0, "is_active": 0}},
			)
			fmt.Println(change, err)
		}
	}

	return change, nil
}

// hash password bcrypt method
func BcryptPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err

}

//CheckPasswordHash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//GenerateJWTToken
func GenerateJWTToken(id string) (string, error) {
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"key": "saurbh",
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"_id": id,
	})
	tokenString, err := token.SignedString([]byte(id))
	fmt.Println(tokenString)
	return tokenString, err
}
