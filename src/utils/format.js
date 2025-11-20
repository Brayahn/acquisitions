//returning specific errors for issues 


export const formatValidationError = (errors) => {

  if (!errors || !errors.issues) return 'Validation Successful';

  if (Array.isArray(errors.issues)) return errors.issues.map (i=>i.message).join(',');
  return JSON.stringify(errors);

};