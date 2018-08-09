api : 

localhost:8090/user/v1/get

localhost:8090/user/v1/login

localhost:8090/user/v1/details

localhost:8090/user/v1/forgotPassword

localhost:8090/user/v1/verifyCode

localhost:8090/user/v1/changePassword

localhost:8090/user/v1/signOut

collection schema{
  first_name : {type :string, required: true }
  last_name :  {type:string, required: true} 
  user_name: { type:string, unique:true},
  email:  { type :string, unique: true},
  mobile_no: {type :number, unique: true},
  password: (type :string , required: true }
  is_actinve : type{min: 0, max: 1 }
  jwt :  {type string}
is_jwt_active:type{min: 0, max: 1  }
validUpto :date 
verificationCode: number
}
  start api :
  go run main.go
  
  sry  i didn't match your deadline..

  