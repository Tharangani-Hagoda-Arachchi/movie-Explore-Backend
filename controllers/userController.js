import { AppError } from '../middlewares/errorHandler.js'; 
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import User from '../models/userModel.js';
dotenv.config();

const jwtSecret = process.env.JWT_SECRET;


// user signup
export const Signup = async (req, res, next) => {
    try{
        const { userName,userPassword } = req.body

        // check user name is already exists
        const existingUser = await User.findOne({ userName });
        if (existingUser) {
            return res.status(400).json({ message: 'User Name is already registered' });
        }


        // create nwe user
        const newUser = new User({
            userName,
            userPassword
        });

        await newUser.save();

        res.status(201).json({ message: 'Signup successful' });
        next()


    } catch(error){
        next(error); // Pass error to the global error handler
    }
};



//user login
export const Login = async (req, res, next) => {
    try{
        const { userName,userPassword} = req.body
        
        if (!userName || !userPassword) {
            throw new AppError('Username and password are required', 422, 'ValidationError');
        }

        const user = await User.findOne({userName})

        if (!user){
            throw new AppError('Username password are invalid', 401, 'AuthenticationError');
        }

        const passwordMatch = await bcrypt.compare(userPassword, user.userPassword)

        if (!passwordMatch) {
            throw new AppError('Username or Password invalid', 401, 'AuthenticationError');
        }

        //create jwt token
        const accessToken = jwt.sign({userId: user._id}, jwtSecret, { subject: 'AccessAPI', expiresIn: '15m'})

       
        res.status(200).json({
            success: true,
            message: 'Login successful',
            accessToken,
        });

        next()   

    } catch(error){
        next(error)
    }
}




