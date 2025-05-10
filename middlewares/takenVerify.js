import jwt from 'jsonwebtoken';
import { AppError } from '../middlewares/errorHandler.js'; 

const jwtSecret = process.env.JWT_SECRET;

export const verifyToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      throw new AppError('Authorization header is missing', 401, 'AuthenticationError');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new AppError('Token not found', 401, 'AuthenticationError');
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
      if (err) {
        throw new AppError('Invalid or expired token', 403, 'AuthenticationError');
      }

      res.status(200).json({
        success: true,
        message: 'Token is valid',
        userId: decoded.userId,
      });
    });
  } catch (error) {
    next(error);
  }
};
