import jwt from 'jsonwebtoken';
import config from '../config.json';
import db from '../_helpers/db';

const { secret } = config;

function getTokenFromRequest(req: any) {
    const headers = req.headers || {};
    const tokenSource =
        req.get?.('Authorization') ||
        headers.authorization ||
        headers.Authorization ||
        headers['x-access-token'] ||
        headers['x-accesstoken'] ||
        headers['authorization-token'] ||
        req.query?.token ||
        req.cookies?.jwtToken ||
        req.cookies?.refreshToken;

    if (!tokenSource) return null;
    const tokenString = Array.isArray(tokenSource) ? tokenSource[0] : tokenSource.toString();
    const match = tokenString.match(/Bearer\s+(.+)/i);
    return match ? match[1] : tokenString;
}

export default function authorize(roles: any =[]) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return async (req: any, res: any, next: any) => {
        const token = getTokenFromRequest(req);
        if (!token) {
            return res.status(401).json({ message: 'No authorization token provided' });
        }

        let payload: any;
        try {
            payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
        } catch (err: any) {
            return res.status(401).json({ message: err?.message || 'Invalid token' });
        }

        const accountId = payload && (payload.id || payload.sub || payload.userId);
        if (!accountId) {
            return res.status(401).json({ message: 'Token payload missing user id' });
        }

        const account = await db.Account.findByPk(accountId);
        if (!account) {
            return res.status(401).json({ message: 'Account not found' });
        }

        if (roles.length && !roles.includes(account.role)) {
            return res.status(403).json({ message: `Admin role required; current role is ${account.role}` });
        }

        req.user = { id: accountId, role: account.role, ...payload };
        const refreshTokens = await account.getRefreshTokens();
        req.user.ownToken = (refreshToken: any) => !!refreshTokens.find((x: any) => x.token === refreshToken);
        next();
    };
}
