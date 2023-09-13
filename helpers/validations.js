const Joi = require("joi");

 
const adminValidation = (data) => {
  const schema = Joi.object({
    name: Joi.string().pattern(/^[a-zA-Z]+$/).min(5).max(30).optional(),
    email: Joi.string().email().min(5).max(250).required(),
    password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required(),
    admintype: Joi.string().required(),
  });

  return schema.validate(data);
};
const validateNewAdmin= (data) => {
  const schema = Joi.object({
    name: Joi.string().pattern(/^[a-zA-Z]+$/).min(5).max(30).required().messages({
      'string.pattern.base': 'Name must contain only letters',
      'string.empty': 'Name is required',
      'string.min': 'Name should have a minimum length of {#limit}',
      'string.max': 'Name should have a maximum length of {#limit}',
      'any.required': 'Name is required',
    }),
    email: Joi.string().email().min(5).max(250).required().messages({
    'string.email': 'Invalid email format',
    'string.empty': 'Email is required',
    'string.min': 'Email should have a minimum length of {#limit}',
    'string.max': 'Email should have a maximum length of {#limit}',
    'any.required': 'Email is required'
  }),
  password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
    'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
    'string.empty': 'Password is required',
    'any.required': 'Password is required'
  }),
  admintype:Joi.string().required(),

});

  return schema.validate(data);
};
const registrationValidation = (data) => {
    const schema = Joi.object({
      
      name: Joi.string().pattern(/^[a-zA-Z]+$/).min(3).max(30).required(),
      email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
    phone: Joi.string().pattern(/^[6789]\d{9}$/).required().messages({
      'string.pattern.base': 'Phone number should start with 6, 7, 8 or 9 and have 10 digits',
      'string.empty': 'Phone number is required',
      'any.required': 'Phone number is required'
    }),
    
  
 });
  
    return schema.validate(data);
  };
  const hrregistration = (data) => {
    const schema = Joi.object({
      
      Name: Joi.string().pattern(/^[a-zA-Z]+$/).min(3).max(30).required(),
      Email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    Password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
    Phone_Number: Joi.string().pattern(/^[6789]\d{9}$/).required().messages({
      'string.pattern.base': 'Phone number should start with 6, 7, 8 or 9 and have 10 digits',
      'string.empty': 'Phone number is required',
      'any.required': 'Phone number is required'
    }),
   
  });
  
    return schema.validate(data);
  };
  const loginValidation = (data) => {
    const schema = Joi.object({
    password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
    EmailOrPhone_Number: Joi.string().required().messages({
      'string.empty': 'Email or Phone number is required',
      'any.required': 'Email or Phone number is required'
    })
    });
return schema.validate(data);
  };
  const loginemployee = (data) => {
    const schema = Joi.object({
    password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
    email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    });
return schema.validate(data);
  };
  const loginval = (data) => {
    const schema = Joi.object({
    password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
    phone: Joi.string().pattern(/^[6789]\d{9}$/).required().messages({
      'string.pattern.base': 'Phone number should start with 6, 7, 8 or 9 and have 10 digits',
      'string.empty': 'Phone number is required',
      'any.required': 'Phone number is required'
    }),
    });
return schema.validate(data);
  };
 

const Categoriesvalidation = (data) => {
  const schema = Joi.object({
    categories: Joi.array().items(Joi.string()).min(1).required().messages({
      "array.empty": "At least one category is required",
      "any.required": "At least one category is required",
    }),
  });

  return schema.validate(data);
};
const validate =(data)=>{
  const schema=Joi.object({
     enc:Joi.string().required()
    
  })
  return schema.validate(data);
}
const validatepost=(post)=>{
  const schema = Joi.object({
    title: Joi.string().min(10).max(100).required().messages({
      'string.empty': 'Title is required',
      'any.required': 'Title is required'
    }),
    description:Joi.string().min(100).max(500).required().messages({
      'string.empty': 'Description is required',
      'any.required': 'Description is required'
    }),
    categories:Joi.string().min(1).required().messages({
      'array.empty': 'At least one category is required',
      'any.required': 'At least one category is required'
    }),
    price: Joi.number().min(10).max(10000000).required().messages({
      'number.min': 'Price must be greater than or equal to 0',
      'any.required': 'Price is required'
    }),
    images: Joi.string().required().messages({
      'array.empty': 'At least one image is required',
      'any.required': 'At least one image is required'
    })
  });

  return schema.validate(post);
}

const validatePassword=(data)=>{
   const schema = Joi.object({
  
    Email: Joi.string().email().min(5).max(250),
   
    newpassword: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
     
    }),
    conformpassword:Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
      'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
     
    }),
  });

  return schema.validate(data);
}

const employeeregister=(data)=>{
   const schema = Joi.object({
      employeeID: Joi.string().required(),
      firstName: Joi.string().required(),
      lastName: Joi.string().required(),
      nickName: Joi.string(),
      Email: Joi.string().email().required(),
      Password:Joi.string().required(),
      organisation:Joi.string().required(),
      workInformation: Joi.object({
        department: Joi.string().required(),
        location: Joi.string().required(),
        designation: Joi.string().required(),
        zohoRole: Joi.string().required(),
        employmentType: Joi.string().required(),
        employeeStatus: Joi.string(),
        sourceOfHire: Joi.string(),
        dateOfJoining: Joi.date().required(),
      }),
      HierarchyInformation: Joi.object({
        reportingManager: Joi.object({
          employeeID: Joi.string(),
          firstName: Joi.string(),
          lastName: Joi.string(),
        }),
      }),
      personalDetails: Joi.object({
        dateOfBirth: Joi.date(),
        maritalStatus: Joi.string(),
        aboutMe: Joi.string(),
        askMeAbout: Joi.string(),
        expertise: Joi.string(),
      }),
      contactDetails: Joi.object({
        workPhoneNumber: Joi.string(),
        extension: Joi.string(),
        seatingLocation: Joi.string(),
        tags: Joi.string(),
        personalMobileNumber: Joi.string(),
        personalEmailAddress: Joi.string().email(),
      }),
      systemFields: Joi.object({
        addedBy: Joi.object({
          employeeID: Joi.string(),
          firstName: Joi.string(),
          lastName: Joi.string(),
          middleName: Joi.string(),
        }),
        addedTime: Joi.date().default(Date.now()),
        modifiedBy: Joi.object({
          employeeID: Joi.string(),
          firstName: Joi.string(),
          lastName: Joi.string(),
          middleName: Joi.string(),
        }),
        modifiedTime: Joi.date().default(Date.now()),
      }),
      workExperience: Joi.array().items(
        Joi.object({
          company: Joi.string(),
          jobTitle: Joi.string(),
          startDate: Joi.date(),
          endDate: Joi.date(),
          jobdescription: Joi.string(),
        })
      ),
      educationDetails: Joi.array().items(
        Joi.object({
          instituteName: Joi.string(),
          degreeOrDiploma: Joi.string(),
          specialization: Joi.string(),
          dateOfCompletion: Joi.date(),
        })
      ),
      dependentDetails: Joi.array().items(
        Joi.object({
          Name: Joi.string(),
          Relationship: Joi.string(),
          DateOfBirth: Joi.date(),
        })
      ),
    });

return schema.validate(data);
}



const departmentvalidation=(data)=>{
  const schema =  Joi.object({
    departmentName: Joi.array()
    .items(Joi.string().min(3).max(50).pattern(/^[a-zA-Z0-9 ]+$/)).unique().required().messages({
      'array.empty': 'At least one department name is required',
      'any.required': 'At least one department name is required',
      'array.unique': 'Duplicate department names are not allowed',
      'string.min': 'Department name must be at least 3 characters long',
      'string.max': 'Department name must not exceed 50 characters',
      'string.pattern.base': 'Department name must contain only letters, numbers, and spaces' }),
      mailAlias: Joi.string().required(),
      departmentLead:Joi.string().required(),
      parentDepartment:Joi.string().required(),
      addedBy:Joi.string().required(),
      modifiedBy:Joi.string().required()

    });
  return schema.validate(data);
}

const designationvalidation=(data)=>{
  const schema = Joi.object({
  designationName:Joi.array()
  .items(Joi.string().min(3).max(50).pattern(/^[a-zA-Z0-9 ]+$/)).unique().required().messages({
    'array.empty': 'At least one designation name is required',
    'any.required': 'At least one designation name is required',
    'array.unique': 'Duplicate designation names are not allowed',
    'string.min': 'Designation name must be at least 3 characters long',
    'string.max': 'Designation name must not exceed 50 characters',
    'string.pattern.base': 'Designation name must contain only letters, numbers, and spaces' }),
  mailAlias: Joi.string().required(),
  addedBy: Joi.string().required(),
  modifiedBy: Joi.string().required(),
  
});
return schema.validate(data);
}
function validatecompanytimingsdata(companytimings) {
  const schema = Joi.object({
    organisation:Joi.string().required(),
    inTime: Joi.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    outTime: Joi.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  });
  return schema.validate(companytimings);
}
function validatecompanydata(companydetails) {
  const schema = Joi.object({
    organisation:Joi.string().required(),
    established: Joi.string().min(3).required(),
    type: Joi.string().min(5).required(),
    companyIdCode: Joi.string().regex(/[A-Z]/).required(),
    companyMailId: Joi.string().min(5).email().required(),
    companyContactNumber: Joi.string()
      .length(10)
      .pattern(/^[6-9]{1}[0-9]{9}$/)
      .required(),
  });
  return schema.validate(companydetails);
}



const employeecheckin=(data)=>{
  const schema =  Joi.object({
    employeeID:Joi.string().required(),
    checkIn: Joi.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  
});
return schema.validate(data);
}
const employeecheckout=(data)=>{

  const schema =  Joi.object({
    employeeID:Joi.string().required(),
    checkOut: Joi.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
});
return schema.validate(data);
}
const leavevalidation=(data)=>{
  const schema =  Joi.object({
  employeeID: Joi.string().required(),
  leaveType: Joi.string().min(4).required(),
  fromDate: Joi.date().required(),
  toDate: Joi.date().required(),
  teamEmailID: Joi.string().email().required(),
  reason: Joi.string().required(),
});
return schema.validate(data);
}
const validateregistration=(data)=> {
  const schema = Joi.object({
   
  password: Joi.string().required(),
  phone: Joi.string().pattern(/^[6-9]\d{9}$/).required().messages({
      'string.pattern.base': 'Invalid phone number',
    }),
    username:Joi.string().pattern(/^[^\s]+$/).required().messages({
      'string.pattern.base': 'Username must not contain spaces',
    }),
    password: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
    })
  });

  return schema.validate(data);
}
const admincontrolsvalidations=(data)=> {
  const schema = Joi.object({
    register: Joi.string().valid('Enable', 'Disable').required(),
    login: Joi.string().valid('Enable', 'Disable').required(),
    transactions: Joi.string().valid('Enable', 'Disable').required(),
    balances: Joi.string().valid('Enable', 'Disable').required(),
    bitcoin: Joi.number().required().min(100).max(5000),
    peso: Joi.number().required().min(100).max(5000),
    usdt: Joi.number().required().min(100).max(3000),
    busd: Joi.number().required().min(100).max(4000),
    trans: Joi.number().required().min(1000).max(1000000)
  });
return schema.validate(data);
}
const loginadmin = (data) => {
  const schema = Joi.object({
  password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
    'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
    'string.empty': 'Password is required',
    'any.required': 'Password is required'
  }),
  email: Joi.string().email().min(5).max(250).required().messages({
    'string.email': 'Invalid email format',
    'string.empty': 'Email is required',
    'string.min': 'Email should have a minimum length of {#limit}',
    'string.max': 'Email should have a maximum length of {#limit}',
    'any.required': 'Email is required'
  }),
  });
return schema.validate(data);
};

const loginuser = (data) => {
  const schema = Joi.object({
  password: Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).required().messages({
    'string.pattern.base': 'Password should contain at least one uppercase letter, one lowercase letter, one number and one special character',
    'string.empty': 'Password is required',
    'any.required': 'Password is required'
  }),
  email: Joi.string().email().min(5).max(250).required().messages({
    'string.email': 'Invalid email format',
    'string.empty': 'Email is required',
    'string.min': 'Email should have a minimum length of {#limit}',
    'string.max': 'Email should have a maximum length of {#limit}',
    'any.required': 'Email is required'
  }),
  });
return schema.validate(data);
};
const validateemail = (data) => {
  const schema = Joi.object({
   email: Joi.string().email().min(5).max(250).required().messages({
    'string.email': 'Invalid email format',
    'string.empty': 'Email is required',
    'string.min': 'Email should have a minimum length of {#limit}',
    'string.max': 'Email should have a maximum length of {#limit}',
    'any.required': 'Email is required'
  })
  });
return schema.validate(data);
};

const twofactorRegistration=(data)=> {
  const schema = Joi.object({
  username: Joi.string().pattern(/^[a-zA-Z]+$/).min(3).max(30).required(),
  email: Joi.string().email().min(5).max(250).required().messages({
    'string.email': 'Invalid email format',
    'string.empty': 'Email is required',
    'string.min': 'Email should have a minimum length of {#limit}',
    'string.max': 'Email should have a maximum length of {#limit}',
    'any.required': 'Email is required'
  }),
  password: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
    'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
  }),
  kyc_details: Joi.object(),
  last_login_ip: Joi.string().required(),
  fcm_token: Joi.string().required(),
  balances:Joi.array(),
  referral_one: Joi.string().required(),
 
});

return schema.validate(data);
}
const loginverify = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    otp: Joi.string().length(6).pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'OTP should be a 6-digit number',
      'string.empty': 'OTP is required',
      'string.length': 'OTP should have exactly 6 digits',
      'any.required': 'OTP is required'
    }),
    twoFaCode: Joi.string().pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'TwoFaCode should be a number',
      'string.empty': 'TwoFaCode is required',
      'any.required': 'TwoFaCode is required'
    }),
  });
  return schema.validate(data);
};
const resetpassword = (data) => {
  const schema = Joi.object({
    
    email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    otp: Joi.string().length(6).pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'OTP should be a 6-digit number',
      'string.empty': 'OTP is required',
      'string.length': 'OTP should have exactly 6 digits',
      'any.required': 'OTP is required'
    }),
    twoFaCode: Joi.string().pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'TwoFaCode should be a number',
      'string.empty': 'TwoFaCode is required',
      'any.required': 'TwoFaCode is required'
    }),
    newPassword: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
    })
  });
  return schema.validate(data);
};
const updatecoinbalance = (data) => {
  const schema = Joi.object({
    
    email: Joi.string().email().min(5).max(250).required().messages({
      'string.email': 'Invalid email format',
      'string.empty': 'Email is required',
      'string.min': 'Email should have a minimum length of {#limit}',
      'string.max': 'Email should have a maximum length of {#limit}',
      'any.required': 'Email is required'
    }),
    coinname:Joi.string().required(),
    amount:Joi.string().required()
   
  });
  return schema.validate(data);
};
const validateresetpassword = (data) => {
  const schema = Joi.object({
    adminId:Joi.string().required(),
    newPassword: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
    })
  });
  return schema.validate(data);
};
const validateadmintype = (data) => {
  const schema = Joi.object({
    adminId:Joi.string().required(),
    admintype:Joi.string().required(),
  });
  return schema.validate(data);
};
const validateadminid = (data) => {
  const schema = Joi.object({
    adminId:Joi.string().required()
    
  });
  return schema.validate(data);
};
const validatecoin = (data) => {
  const schema = Joi.object({
    userid:Joi.string().required(),
    coinid:Joi.string().required()
    
  });
  return schema.validate(data);
};
const validatelimit = (data) => {
  const schema = Joi.object({
    limit: Joi.number().integer().required(), 
  });
  return schema.validate(data);
};
const validateuserscoin = (data) => {
  const schema = Joi.object({
    
    coinid:Joi.string().required()
    
  });
  return schema.validate(data);
};
const changepassword = (data) => {
  const schema = Joi.object({
   
    otp: Joi.string().length(6).pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'OTP should be a 6 digit number',
      'string.empty': 'OTP is required',
      'string.length': 'OTP should have exactly 6 digits',
      'any.required': 'OTP is required'
    }),
    twoFaCode: Joi.string().length(6).pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'TwoFaCode should be a 6-digit number',
      'string.empty': 'TwoFaCode is required',
      'string.length': 'TwoFaCode should have exactly 6 digits',
      'any.required': 'TwoFaCode is required'
    }),
    oldPassword: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
    }),
    newPassword: Joi.string().pattern(/^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/).required().messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character, and be at least 8 characters long',
    })
  });
  return schema.validate(data);
};
const verifytwofa = (data) => {
  const schema = Joi.object({
   
    twoFaCode: Joi.string().length(6).pattern(/^\d+$/).required().messages({
      'string.pattern.base': 'TwoFaCode should be a 6-digit number',
      'string.empty': 'TwoFaCode is required',
      'string.length': 'TwoFaCode should have exactly 6 digits',
      'any.required': 'TwoFaCode is required'
    })
   
  });
  return schema.validate(data);
};
const validatecoins = (data) => {
  const schema = Joi.object({
    coinName: Joi.string().required(),
    ticker:Joi.string().required(),
    coinStatus: Joi.string().required(),
    withdrawMin: Joi.number().min(100).required(),
    withdrawMax: Joi.number().max(1000000).required(),
    withdrawFeeType: Joi.string().required(),
    withdrawFee: Joi.number().required(),
    withdrawStatus: Joi.string().required(),
    depositMin: Joi.number().min(100).required(),
    depositMax: Joi.number().max(1000000).required(),
    depositFeeType: Joi.string().required(),
    depositStatus:Joi.string().required(),
    depositFee: Joi.number().required(),
    note: Joi.string()
  });
  return schema.validate(data);
};

const validateadmincontrols = (data) => {
  const schema = Joi.object({
  Register: Joi.string().valid('Enable', 'Disable').default('Disable'),
  login: Joi.string().valid('Enable', 'Disable').default('Disable'),
  Transfer: Joi.string().valid('Enable', 'Disable').default('Disable'),
  
});
return schema.validate(data);
};
const validatecontrols = (data) => {
  const schema = Joi.object({
    name: Joi.string().valid('Register', 'login', 'Transfer').required(),
    value: Joi.string().valid('Enable', 'Disable').required()
  });

  return schema.validate(data);
};

const validateenc=(data) => {
  const schema = Joi.object({
    enc: Joi.string().required(),
  });
  return schema.validate(data);
};





module.exports = {
  validateregistration,
  registrationValidation,
  employeecheckin,
  employeecheckout,
  loginValidation,
  Categoriesvalidation,
  validate,
  validatepost,
  hrregistration,
  validatePassword,
  departmentvalidation,
  designationvalidation,
  employeeregister,
  validatecompanydata,
  validatecompanytimingsdata,
  leavevalidation,
  loginemployee,
  loginval,
  admincontrolsvalidations,
  adminValidation,
  loginadmin,
  twofactorRegistration,
  validateemail,
  loginverify,
  resetpassword,
  changepassword,
  verifytwofa,
  validateNewAdmin,
  validateresetpassword,
  validateadmintype,
  validateadmincontrols,
  validatecoins,
  validatecontrols,
  validateadminid,
  loginuser,
  validatecoin,
  validateuserscoin,
  updatecoinbalance,
  validatelimit,
  validateenc

};


  