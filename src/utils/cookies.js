export const cookies = {

  //getting the cookie options
  getOptions: () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  }),

  //set cookies
  set: (res,name,value,options={})=>{
    res.cookie(name, value, {...cookies.getOptions(), ...options });
  },

  //clearing the cookie sessions 
  clear : (res,name,options={})=>{
    res.clearCookie(name, {...cookies.getOptions(), ...options });
  },

  //accessing the cookie once it has been set
  get: (req,name)=>{
    return req.cookies[name];
  }
};