import express, { response } from "express";
import dotenv from "dotenv";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
dotenv.config();
const app = express();
const port = process.env.PORT;

app.use(express.json());
app.use(cors());

const uri = process.env.URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});



const jwtMidelWear =  (req, res, next) => {
    const token = req?.heders?.authorization || undefined;
    if(!token){
        return res.status(400).json({
            message:"You are Not authorized"
        })
    }

    jwt.verify(token, process.env.JWT_SECRRECT_KEY, (err, decoadeData) => {
        if(err){
            return res.status(400).json({
             essage: "Your are not authorized",
             err   
            })
        }
        req.user = decoadeData;
        next();
    })
}

async function run() {
  try {
    await client.connect();
    const db = client.db("servetest");
    const userCollections = db.collection("useroll");

    app.post("/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;

        // chack
        const exgisting = await userCollections.findOne({ email });
        if (exgisting) {
          return res.status(409).json({
            message: "This Email Allready Exgisties Login Now",
          });
        }

        const hashPassowrdSedDb = await bcrypt.hash(password, 15);
        const result = await userCollections.insertOne({
          name,
          email,
          password: hashPassowrdSedDb,
        });

        res.status(200).json({
          message: "User Creat Successfully",
          result,
        });
      } catch (err) {
        console.log(err);
        res.status(400).json({
          message: "Bad Request",
        });
      }
    });

    app.post("login", async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await userCollections.findOne({
          email,
        });

        const isMatchPassowrd = await bcrypt.compare(password, user.password);

        if (!isMatchPassowrd) {
          return res.status(400).json({
            message: "Password incorrect!",
          });
        }

        const token = jwt.sign(
          {
            email: user.email,
            _id: user._id,
          },
          process.env.JWT_SECRRECT_KEY,
          { expiresIn: "12h" }
        );

        res.status(200).json({
          message: "Logged in Succeddfully",
          token,
        });
      } catch (err) {
        console.log(err);
      }
    });

    app.get("/me", async (req, res) => {
      try {
        const user = req.user;
        const userData = await userCollections.findOne(
          { _id: new ObjectId(user._id) },
          { projection: { password: 0 } }
        );

        res.status(200).json({
          message: "Current User",
          userData,
        });
      } catch (err) {
        res.status(400).json({
          message: "Unothriged Access",
        });
        console.log(err);
      }
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
