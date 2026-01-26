namespace go user

struct LoginReq {
    1: string userId (api.query="userId");
}

struct LoginResp {
    1: string token;
}

struct MessageResp {
    1: string message;
}

struct UserInfoResp {
    1: string loginId;
    2: list<string> roles;
    3: list<string> permissions;
}

struct SensitiveResp {
    1: bool sensitive;
}

service UserService {
    LoginResp Login(1: LoginReq request) (api.get="/login");
    MessageResp Public() (api.get="/public");
    UserInfoResp UserInfo() (api.get="/user");
    MessageResp Admin() (api.get="/admin");
    MessageResp Manager() (api.get="/manager");
    MessageResp Disable() (api.get="/disable");
    SensitiveResp Sensitive() (api.get="/sensitive");
}