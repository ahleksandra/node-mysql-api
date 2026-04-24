import nodemailer from 'nodemailer';
import config from '../config.json';

export default async function sendEmail({to, subject, html, from = config.emailFrom}: any){
    const transporter = nodemailer.createTransport(config.smtpOptions);
    await transporter.sendMail({from, to, subject, html});
}