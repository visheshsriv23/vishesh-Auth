import UserModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import SessionModel from "../models/session.model.js";

export async function register(req, res) {
  try {
    const { username, email, password } = req.body;

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
        res.status(400).json({ message: "User already exists" });
        return;
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    const user = await UserModel.create({ username, email, password: hashedPassword });
    const refreshToken = jwt.sign({ id: user._id }, config.jwtSecret, { expiresIn: "1d" });
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await SessionModel.create({ userId: user._id, refreshTokenHash, ip: req.ip, userAgent: req.headers["user-agent"] });
    const accessToken = jwt.sign({ id: user._id, sessionId: session._id }, config.jwtSecret, { expiresIn: "15m" });

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    res.status(201).json({ 
        message: "User registered successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        },
        accessToken,
     });
 }
 catch (error) {
    res.status(500).json({ message: "Internal server error" });
 }
}

export async function login(req, res) {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });
    if(!user) {
        res.status(401).json({ message: "Invalid email or password" });
        return;
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    const isPasswordValid = hashedPassword === user.password;
    if(!isPasswordValid) {
        res.status(401).json({ message: "Invalid email or password" });
        return;
    }
    const refreshToken = jwt.sign({ id: user._id }, config.jwtSecret, { expiresIn: "7d" });
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await SessionModel.create({ userId: user._id, refreshTokenHash, ip: req.ip, userAgent: req.headers["user-agent"] });
    const accessToken = jwt.sign({ id: user._id, sessionId: session._id }, config.jwtSecret, { expiresIn: "15m" });
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    res.status(200).json({
        message: "User logged in successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        },
        accessToken
    });
}

export async function getMe(req, res) {
    const token = req.headers.authorization?.split(" ")[1];
    if(!token) {
        res.status(401).json({ message: "No token provided" });
        return;
    }
    const decoded = jwt.verify(token, config.jwtSecret);
    console.log(decoded);
    const user = await UserModel.findById(decoded.id);
    res.status(200).json({
        message: "User fetched successfully",
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    });
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        res.status(401).json({ message: "No refresh token provided" });
        return;
    }
    try {
        const decoded = jwt.verify(refreshToken, config.jwtSecret);
        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        const session = await SessionModel.findOne({ refreshTokenHash, revoked: false });
        if(!session) {
            res.status(401).json({ message: "Invalid refresh token" });
            return;
        }
        const user = await UserModel.findById(decoded.id);
        const newAccessToken = jwt.sign({ id: user._id }, config.jwtSecret, { expiresIn: "15m" });
        const newRefreshToken = jwt.sign({ id: user._id }, config.jwtSecret, { expiresIn: "1d" });
        const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });
        res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken: newAccessToken
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid refresh token" });
    }
}

export async function logout(req, res){
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        res.status(400).json({
            message: "Refresh Token not found"
        })
    }
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await SessionModel.findOne({ refreshTokenHash, revoked: false });
    if(!session){
        res.status(400).json({
            message: "Session not found"
        })
    }
    session.revoked = true;
    await session.save();
    res.clearCookie("refreshToken");
    res.status(200).json({
        message: "Logged out successfully"
    })
}

export async function logoutAll(req, res){
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        res.status(400).json({
            message: "Refresh Token not found"
        })
    }
    const decoded = jwt.verify(refreshToken, config.jwtSecret);
    await SessionModel.updateMany({ userId: decoded.userId, revoked: false }, { revoked: true });
    res.clearCookie("refreshToken");
    res.status(200).json({
        message: "Logged out from all sessions successfully"
    })
}
