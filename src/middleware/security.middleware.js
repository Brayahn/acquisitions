import aj from '#config/arcjet.js';
import { slidingWindow } from '@arcjet/node';
import logger from '#config/logger.js';

const securityMiddleware = async (req,res,next) =>{
  try {
    const role = req.user?.role || 'guest';

    let limit;
    let message;
        
    switch (role) {
      case 'admin':
        limit = 20;
        message = 'Admin request limit exceeded(20 per minute). Slow down';
        break;

      case 'user':
        limit = 10;
        message = 'User request limit exceeded(10 per minute). Slow down';
        break;

      case 'guest':
        limit = 3;
        // eslint-disable-next-line no-unused-vars
        message = 'Guest request limit exceeded(20 per minute). Slow down';
        break;       
    }


    const client = aj.withRule(slidingWindow({
      mode: 'LIVE',
      interval: '1m',
      max: limit,
      name: `${role}-rate-limit`
    }));


    const decision = await client.protect(req);

    //BOT BLOCK 
    if (decision.isDenied() && decision.reason.isBot()){
      logger.warn('Bot request blocked', 
        {ip: req.ip, 
          useAgent: req.get('User-Agent'),
          path: req.path
        }
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Automated requests are not allowed'
      });
    }


    //SHIELD BLOCK 
    if (decision.isDenied() && decision.reason.isShield()){
      logger.warn('Shield Blocked Request', 
        {ip: req.ip, 
          useAgent: req.get('User-Agent'),
          path: req.path,
          method: req.method
        }
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request blocked by security policy'
      });
    }


    //RATE LIMIT EXCEEDED
    if (decision.isDenied() && decision.reason.isRateLimit()){
      logger.warn('Rate Limit exceeded', 
        {ip: req.ip, 
          useAgent: req.get('User-Agent'),
          path: req.path
        }
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Too many requests!'
      });
    }

    next();
  } catch (e) {
    console.log ('Arcje Middleware Error', e);
    res.status(500).json({error: 'Internal Server Error', 
      message: 'Something went wrong with the Security Middleware'});
  }
};

export default securityMiddleware;