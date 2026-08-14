import { Router } from "express";
import { register, getMe, refreshToken, logout, logoutAll, login } from "../controller/auth.controller.js";

const authrouter = Router();

authrouter.post("/register", register);
authrouter.post("/login", login); 
authrouter.get("/get-me", getMe);
authrouter.get("/refresh-token", refreshToken);
authrouter.get("/logout", logout);
authrouter.get("/logout-all", logoutAll);

export default authrouter;