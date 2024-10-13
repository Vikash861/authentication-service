import UserModel, { IUser } from "../models/User.js";

const findUserByEmail = async (email: string): Promise<IUser | null> => {
    return await UserModel.findOne({ email }).exec();;
};

export default findUserByEmail;
