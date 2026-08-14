import app from "./src/app.js";
import connectDB from "./config/db.js";

connectDB();
const port = 3005;

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
})