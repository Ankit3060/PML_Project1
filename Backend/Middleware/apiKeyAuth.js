export const verifyApiKey = (req, res, next) => {
    const clientKey = req.header("x-api-key");

    if (!clientKey || clientKey !== process.env.API_KEY) {
        return res.status(403).json({ message: "Forbidden: Invalid API Key" });
    }

    next();
};
