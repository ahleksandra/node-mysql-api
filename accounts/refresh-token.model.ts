import { DataTypes } from "sequelize";

export default function model(sequelize: any){
    const attributes = {
    token: { type: DataTypes.STRING},
    expires: {type: DataTypes.DATE},
    created: {type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW},
    createdByIp: {type: DataTypes.STRING},
    revoked: {type: DataTypes.DATE},
    revokedByIp: {type: DataTypes.STRING},
    replacedByToken: {type: DataTypes.STRING},
    isExpired: {
        type: DataTypes.VIRTUAL,
        get() {return Date.now() >= this.expires;}
    },
    isActive: {
        type: DataTypes.VIRTUAL,
        get(){ return !this.revoked && !this.isExpired; }
    }
 };

    const options = { timeStamps: false };
    return sequelize.define('refreshToken', attributes, options);
}