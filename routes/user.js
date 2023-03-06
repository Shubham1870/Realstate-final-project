const express = require("express")
const router = express.Router()
const bcrypt = require("bcrypt")
const dotenv = require("dotenv")
const usermodel = require("../models/user-model")
const cors = require("cors")
const jwt = require("jsonwebtoken")


const salt = 10;
dotenv.config()
router.use(cors());

//ALL USER
router.get('/alluser', async (req, res) => {
    try {
        const data = await usermodel.find();
        res.status(200).json({
            status: "success",
            data
        });
    } catch (err) {
        res.status(400).json({
            status: "failed",
            message: err.message
        })
    }
})

//NEW USER
router.post("/signup", async (req, res) => {
    try {
        const { email, password, confirmpassword } = req.body;
        if (!email || !password || !confirmpassword) {
            return res.status(400).json({
                status: "failed",
                message: "All fields are mandatory",
            });
        }
        const present = await usermodel.findOne({ email });
        if (present) {
            return res.status(400).json({
                status: "failed",
                message: "User already registered",
            });
        }
        if (password !== confirmpassword) {
            return res.status(400).json({
                status: "failed",
                message: "Passwords do not match",
            });
        }
        //HASHING PASSWORD
        bcrypt.hash(password, salt, async function (err, hash) {
            if (err) {
                return res.status(400).json({
                    mesaage: err.message
                })
            }
            //INSERTING NEW USER
            const userData = await usermodel.create({
                email,
                password: hash
            })
            return res.status(200).json({
                message: "success",
                userData
            })

        });
    } catch (e) {
        return res.status(500).json({
            mesaage: "failed"
        })
    }
})


//Signin
router.post("/signin", async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email && password) {
            return res.status(400).json({
                status: "failed",
                message: "All fields required"
            })
        }
        const data = await usermodel.findOne({ email })
        if (!data) {
            return res.status(400).json({
                status: "failed",
                message: "user not registered"
            })
        }
        bcrypt.compare(password, data.password, function (err, result) {
            if (err) {
                return res.status(400).json({
                    status: "failed",
                    message: err.message
                })
            }
            if (result) {
                const token = jwt.sign({
                    payload: data._id
                }, process.env.SECRET_KEY);
                return res.status(200).json({
                    status: "success",
                    message: "Login Succesfull",
                    token,
                    id: data._id
                })
            } else {
                return res.status(400).json({
                    status: "failed",
                    message: "not a valid password"
                })
            }
        });
    } catch (error) {
        return res.status(400).json({
            status: "failed",
            message: error.message
        })
    }
})


module.exports = router