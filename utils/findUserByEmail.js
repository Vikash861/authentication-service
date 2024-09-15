import UserModel from "../models/User.js";

const findUserByEmail = async (email) => {
    return await UserModel.findOne({ email });
};

export default findUserByEmail;