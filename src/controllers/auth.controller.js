import logger from '#config/logger.js';
import { createUser, authenticateUser } from '#services/auth.service.js';
import { cookies } from '#utils/cookies.js';
import { formatValidationError } from '#utils/format.js';
import { jwttoken } from '#utils/jwt.js';
import { signupSchema, signInSchema } from '#validations/auth.validations.js';

export const signup = async (req,res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);
     
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Faied',
        details: formatValidationError(validationResult.error)
      });
    }

    const {name, email, role,password} = validationResult.data;

    //Auth Serice 
    const user = await createUser({name, email, password, role});

    //JWT invocation
    const token = jwttoken.sign ({
      id: user.id,
      email: user.email,
      role:user.role
    }); 
    
    cookies.set(res, 'token', token);

    logger.info(`User registered successfully: ${email}`);
    res.status(201).json ({
      message: 'User Registered',
      user: {
        id:user.id, name: user.name, email: user.email, role: user.role
      }
    });

  } catch (e) {
    logger.error('Sign Up Error', e);

    if (e.message === 'User already exists'){
      return res.status(409).json({error: 'Email already exists'});
    }
    next (e);
  }
};

export const signin = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Faied',
        details: formatValidationError(validationResult.error)
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser({ email, password });

    const token = jwttoken.sign({
      id: user.id,
      email: user.email,
      role: user.role
    });

    cookies.set(res, 'token', token);

    logger.info(`User signed in successfully: ${email}`);

    return res.status(200).json({
      message: 'User Signed In',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (e) {
    logger.error('Sign In Error', e);

    if (e.message === 'Invalid email or password') {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    next(e);
  }
};

export const signout = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User signed out successfully');

    return res.status(200).json({
      message: 'User Signed Out'
    });
  } catch (e) {
    logger.error('Sign Out Error', e);
    next(e);
  }
};
