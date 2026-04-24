import config from '../config.json';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Op } from 'sequelize';
import sendEmail from '../_helpers/send-email';
import db from '../_helpers/db';
import Role from '../_helpers/role';

export default {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

// authentication
async function authenticate({ email, password, ipAddress }: any) {
    const account = await db.Account.scope('withHash').findOne({ where: { email } });

    if (!account || !account.isVerified || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';
    }

    if (account.role !== Role.Admin) {
        const adminCount = await db.Account.count({ where: { role: Role.Admin } });
        if (adminCount === 0) {
            account.role = Role.Admin;
            await account.save();
        }
    }

    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    await refreshToken.save();

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

// refreshing token
async function refreshToken({ token, ipAddress }: any) {
    const refreshToken = await getRefreshToken(token);
    const account = await refreshToken.getAccount();

    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;

    await refreshToken.save();
    await newRefreshToken.save();

    const jwtToken = generateJwtToken(account);

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

// revoking token
async function revokeToken({ token, ipAddress }: any) {
    const refreshToken = await getRefreshToken(token);

    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;

    await refreshToken.save();
}

// registerrr
async function register(params: any, origin: any) {
    const existingAccount = await db.Account.findOne({ where: { email: params.email } });
    if (existingAccount) {
        existingAccount.resetToken = randomTokenString();
        existingAccount.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await existingAccount.save();
        return await sendAlreadyRegisteredEmail(existingAccount, origin);
    }

    const account = new db.Account(params);

    const isFirstAccount = (await db.Account.count()) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = randomTokenString();
    account.passwordHash = await hash(params.password);

    await account.save();

    await sendVerificationEmail(account, origin);
}

// verifying email
async function verifyEmail({ token }: any) {
    const account = await db.Account.findOne({ where: { verificationToken: token } });

    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = null;

    await account.save();
}

// forgot pass
async function forgotPassword({ email }: any, origin: any) {
    const account = await db.Account.findOne({ where: { email } });

    if (!account) return;

    account.resetToken = randomTokenString();
    account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await account.save();

    await sendPasswordResetEmail(account, origin);
}

// validate reset token
async function validateResetToken({ token }: any) {
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [Op.gt]: Date.now() }
        }
    });

    if (!account) throw 'Invalid token';

    return account;
}

// password reset
async function resetPassword({ token, password }: any) {
    const account = await validateResetToken({ token });

    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    account.resetTokenExpires = null;

    await account.save();
}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map((x: any) => basicDetails(x));
}

async function getById(id: any) {
    const account = await getAccount(id);
    return basicDetails(account);
}

// create acc
async function create(params: any) {
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw `Email "${params.email}" is already registered`;
    }

    const account = new db.Account(params);
    account.verified = Date.now();
    account.passwordHash = await hash(params.password);

    await account.save();

    return basicDetails(account);
}

// updating
async function update(id: any, params: any) {
    const account = await getAccount(id);

    if (
        params.email &&
        account.email !== params.email &&
        await db.Account.findOne({ where: { email: params.email } })
    ) {
        throw `Email "${params.email}" is already registered`;
    }

    if (params.password) {
        params.passwordHash = await hash(params.password);
    }

    Object.assign(account, params);
    account.updated = Date.now();

    await account.save();

    return basicDetails(account);
}

async function _delete(id: any) {
    const account = await getAccount(id);
    await account.destroy();
}

// helpers

async function getAccount(id: any) {
    const account = await db.Account.findByPk(id);
    if (!account) throw `Account not found for id ${id}`;
    return account;
}

async function getRefreshToken(token: any) {
    const refreshToken = await db.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive) {
        const looksLikeJwt = typeof token === 'string' && token.split('.').length === 3;
        if (looksLikeJwt) {
            throw 'Invalid refresh token. Use the refresh token, not the access token.';
        }
        throw 'Invalid token';
    }
    return refreshToken;
}

async function hash(password: any) {
    return await bcrypt.hash(password, 10);
}

function generateJwtToken(account: any) {
    return jwt.sign(
        { sub: account.id, id: account.id, role: account.role },
        config.secret,
        { expiresIn: '15m' }
    );
}

function generateRefreshToken(account: any, ipAddress: any) {
    return new db.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account: any) {
    const { id, email, title, firstName, lastName, role, created, updated, isVerified } = account;
    return { id, email, title, firstName, lastName, role, created, updated, isVerified };
}

// 📧 EMAILS

async function sendVerificationEmail(account: any, origin: any) {
    let message;
    const tokenMessage = `<p>Or use this token:</p><p><code>${account.verificationToken}</code></p>`;

    if (origin) {
        const verifyUrl = `${origin}/accounts/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the link to verify your email:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>${tokenMessage}`;
    } else {
        message = `<p>Use this token to verify your email:</p><p><code>${account.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Verify Email',
        html: `<h4>Verify Email</h4><p>Thanks for registering!</p>${message}`
    });
}

async function sendAlreadyRegisteredEmail(account: any, origin: any) {
    let message;
    const tokenMessage = `<p>Or use this token to reset your password:</p><p><code>${account.resetToken}</code></p>`;

    if (origin) {
        const resetUrl = `${origin}/accounts/reset-password?token=${account.resetToken}`;
        message = `<p>Your email is already registered. Click the link below to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>${tokenMessage}`;
    } else {
        message = `<p>Your email is already registered. Use this token to reset your password:</p><p><code>${account.resetToken}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Email Already Registered',
        html: `<h4>Email Already Registered</h4><p>${account.email} is already registered.</p>${message}`
    });
}

async function sendPasswordResetEmail(account: any, origin: any) {
    let message;
    const tokenMessage = `<p>Or use this token:</p><p><code>${account.resetToken}</code></p>`;

    if (origin) {
        const resetUrl = `${origin}/accounts/reset-password?token=${account.resetToken}`;
        message = `<p>Click to reset password (valid 1 day):</p><p><a href="${resetUrl}">${resetUrl}</a></p>${tokenMessage}`;
    } else {
        message = `<p>Use this token:</p><p><code>${account.resetToken}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Reset Password',
        html: `<h4>Reset Password</h4>${message}`
    });
}