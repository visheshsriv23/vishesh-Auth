import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: [true, "User ID is required"]
    },
    refreshTokenHash: {
        type: String,
        required: [true, "Refresh token Hash is required"]
    },
    ip: {
        type: String,
        required: [true, "IP address is required"]
    },
    userAgent: {
        type: String,
        required: [true, "User agent is required"]
    },
    revoked: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600 // Session expires after 1 hour
    }
},
{
    timestamps: true
});

const SessionModel = mongoose.model("Session", sessionSchema);
export default SessionModel;