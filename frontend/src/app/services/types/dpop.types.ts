export interface DPoPRegisterRequest {
  username: string;
  password: string;
}

export interface DPoPRegisterResponse {
  success: boolean;
  message: string;
}

export interface DPoPLoginRequest {
  username: string;
  password: string;
}

export interface DPoPLoginResponse {
  success: boolean;
  message: string;
  username: string;
  accessToken: string;
}

