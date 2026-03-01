const express = require("express")
require("dotenv").config();
// bcrypt : used to hash and compare passwords securely
const bcrypt = require("bcryptjs");

// jwtwebtoken : used to create and verify JWT tokens
const jwt = require("jsonwebtoken");

const mongoose = require("mongoose");


const { intializeDatabase } = require("./db/db.connect");




const Team = require("./models/Team.model.js");
const Project = require("./models/Project.model.js");
const User = require("./models/User.model.js");
const Task = require("./models/Task.model.js");

const app = express();
app.use(express.json());

app.use(async (req, res, next) => {
  try {
    await intializeDatabase();
    next();
  } catch (err) {
    return res.status(500).json({ message: "Database connection failed" });
  }
});

const cors = require("cors");

const allowedOrigins = [
  "http://localhost:5173",
  "https://workasana-frontend-lake.vercel.app",
];

app.use(
  cors({
    origin: (origin, cb) => {
      // allow tools like Postman/curl (no Origin header)
      if (!origin) return cb(null, true);

      if (allowedOrigins.includes(origin)) return cb(null, true);

      return cb(null, false); // or cb(new Error("Not allowed by CORS"))
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);


function signToken(payload) {

  /*
    payload = data we want to store inside token
    Example:
    {
      userId: "...",
      email: "..."
    }
  */
  return jwt.sign(payload, process.env.JWT_SECRET, {
    //secret key (only server knows this)
    expiresIn: process.env.JWT_EXPIRES_IN || "7d", // token validity
  });
}


// Auth Middleware (protect routes)
function requireAuth(req, res, next) {
  /*
    Frontend sends:
    Authorization: Bearer <token>
  */
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");
    // If header is missing or not Bearer

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "Missing or invalid Authorization header" });
  }

  try {
    // Verify token using secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    /*
      decoded looks like:
      {
        userId: "...",
        email: "...",
        iat: ...,
        exp: ...
      }
    */

    // Attaching user info to request object
    req.user = decoded; // { userId, email }
    // Allow request to proceed
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid/expired token" });
  }
}


//register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    // validing input 
    if (!name || !email || !password) {
      return res.status(400).json({ message: "name, email, password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }
    // normalising email
    const emailLower = email.toLowerCase();
    // check if user already exists
    const existing = await User.findOne({ email: emailLower });
    if (existing) return res.status(409).json({ message: "Email already registered" });
    // hashing password
    const passwordHash = await bcrypt.hash(password, 10);
    // saving user in DB
    const user = await User.create({ name, email: emailLower, passwordHash });
    // creating JWT token
    const token = signToken({ userId: user._id.toString(), email: user.email });
    // sending responses (never send passwordHash)
    return res.status(201).json({
      message: "Registered successfully",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

//login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    // validating email and password
    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }
    // finding user by email
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ email: emailLower });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    // comparing password with stored hash
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    // Generate JWT token
    const token = signToken({ userId: user._id.toString(), email: user.email });
    // Send success response
    return res.json({
      message: "Logged in successfully",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  // req.user comes from JWT middleware
  const user = await User.findById(req.user.userId).select("name email createdAt");
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ user });
});


app.get("/",(req,res)=>{
    res.send("Backend is running")
})

//creating the team ( (Protected))
app.post("/api/teams", requireAuth, async (req, res) => {
  try {
    const { name, description, members } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Team name required" });
    }

    const team = await Team.create({
      name,
      description,
      members: members || [],
      owner: req.user.userId  // 🔥 from JWT
    });

    res.status(201).json(team);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: "Team already exists" });
    }
    res.status(500).json({ message: err.message });
  }
});

// List Teams (for cards)
app.get("/api/teams", requireAuth, async (req, res) => {
  const teams = await Team.find({ owner: req.user.userId });
  res.json(teams);
});

//Team Detail (for detail page)

app.get("/api/teams/:id", requireAuth, async (req, res) => {
  const team = await Team.findOne({
    _id: req.params.id,
    owner: req.user.userId
  });

  if (!team) {
    return res.status(404).json({ message: "Team not found" });
  }

  res.json(team);
});

//Add Member (modal action)

app.post("/api/teams/:id/member", requireAuth, async (req, res) => {
  const { memberName } = req.body;

  if (!memberName || !memberName.trim()) {
    return res.status(400).json({ message: "memberName is required" });
  }

  const cleanName = memberName.trim();

  const team = await Team.findOne({
    _id: req.params.id,
    owner: req.user.userId
  });

  if (!team) {
    return res.status(404).json({ message: "Team not found" });
  }

  const exists = team.members.some(
    (m) => m.toLowerCase() === cleanName.toLowerCase()
  );

  if (exists) {
    return res.status(409).json({ message: "Member already exists" });
  }

  team.members.push(cleanName);
  await team.save();

  res.json(team);
});
// delete team member
app.delete("/api/teams/:id/member", requireAuth, async (req, res) => {
  try {
    const { memberName } = req.body;
    if (!memberName || !memberName.trim()) {
  return res.status(400).json({ message: "memberName is required" });
}

    const team = await Team.findOne({
      _id: req.params.id,
      owner: req.user.userId
    });

    if (!team) return res.status(404).json({ message: "Team not found" });

    team.members = team.members.filter(
      (m) => m.toLowerCase() !== memberName.trim().toLowerCase()
    );

    await team.save();
    res.json(team);
  } catch (err) {
    res.status(400).json({ message: "Invalid team id" });
  }
});

//Delete team
app.delete("/api/teams/:id", requireAuth, async (req, res) => {
  const deleted = await Team.findOneAndDelete({
    _id: req.params.id,
    owner: req.user.userId
  });

  if (!deleted) return res.status(404).json({ message: "Team not found" });

  res.json({ message: "Team deleted" });
});

// Create Project
app.post("/api/projects", requireAuth, async (req, res) => {
  const project = await Project.create(req.body);
  res.status(201).json(project);
});

function computeDueOn(createdAt, timeToComplete) {
  const d = new Date(createdAt);
  d.setDate(d.getDate() + Number(timeToComplete || 0));
  return d;
}

/**
 * GET /api/projects/:id/tasks
 * Optional query params:
 *  - ownerId=USER_ID
 *  - tag=ui
 *  - status=To Do|In Progress|Completed|Blocked
 *  - dueFrom=2026-02-01
 *  - dueTo=2026-02-28
 *  - sort=dueAsc|dueDesc|newest|oldest
 */
app.get("/api/projects/:id/tasks", requireAuth, async (req, res) => {
  try {
    const projectId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(projectId)) {
      return res.status(400).json({ message: "Invalid project id" });
    }

    // ensure project exists
    const project = await Project.findById(projectId).select("_id name");
    if (!project) return res.status(404).json({ message: "Project not found" });

    const { ownerId, tag, status, dueFrom, dueTo, sort } = req.query;

    const query = { project: projectId };

    if (ownerId) query.owners = ownerId;
    if (status) query.status = status;
    if (tag) query.tags = { $in: [tag] };

    // Basic fetch first (dueOn is derived, so easiest is filter in JS)
    let tasks = await Task.find(query)
      .populate("project", "name")
      .populate("team", "name")
      .populate("owners", "name email")
      .lean();

    // Add computed dueOn
    tasks = tasks.map((t) => ({
      ...t,
      dueOn: computeDueOn(t.createdAt, t.timeToComplete),
    }));

    // Filter by due date range (since dueOn is computed)
    const from = dueFrom ? new Date(dueFrom) : null;
    const to = dueTo ? new Date(dueTo) : null;
    if (from || to) {
      tasks = tasks.filter((t) => {
        const due = new Date(t.dueOn);
        if (from && due < from) return false;
        if (to) {
          const end = new Date(to);
          end.setHours(23, 59, 59, 999);
          if (due > end) return false;
        }
        return true;
      });
    }

    // Sort
    if (sort === "dueAsc") {
      tasks.sort((a, b) => new Date(a.dueOn) - new Date(b.dueOn));
    } else if (sort === "dueDesc") {
      tasks.sort((a, b) => new Date(b.dueOn) - new Date(a.dueOn));
    } else if (sort === "newest") {
      tasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } else if (sort === "oldest") {
      tasks.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    }

    return res.json({ project, tasks });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

/**
 * POST /api/projects/:id/tasks
 * Body:
 *  {
 *    name: string,
 *    team: TEAM_ID,
 *    owners: [USER_ID],
 *    tags?: [string],
 *    timeToComplete: number,
 *    status?: 'To Do'|'In Progress'|'Completed'|'Blocked'
 *  }
 */
app.post("/api/projects/:id/tasks", requireAuth, async (req, res) => {
  try {
    const projectId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(projectId)) {
      return res.status(400).json({ message: "Invalid project id" });
    }

    // ensure project exists
    const project = await Project.findById(projectId).select("_id name");
    if (!project) return res.status(404).json({ message: "Project not found" });

    const { name, team, owners, tags, timeToComplete, status } = req.body || {};

    // validations based on your schema
    if (!name || !name.trim()) {
      return res.status(400).json({ message: "Task name is required" });
    }
    if (!team) {
      return res.status(400).json({ message: "team is required" });
    }
    if (!Array.isArray(owners) || owners.length === 0) {
      return res.status(400).json({ message: "owners (array) is required" });
    }
    if (timeToComplete === undefined || timeToComplete === null || Number(timeToComplete) <= 0) {
      return res.status(400).json({ message: "timeToComplete must be a positive number" });
    }

    const created = await Task.create({
      name: name.trim(),
      project: projectId,
      team,
      owners,
      tags: Array.isArray(tags) ? tags : [],
      timeToComplete: Number(timeToComplete),
      status: status || "To Do",
    });

    const populated = await Task.findById(created._id)
      .populate("project", "name")
      .populate("team", "name")
      .populate("owners", "name email")
      .lean();

    return res.status(201).json({
      ...populated,
      dueOn: computeDueOn(populated.createdAt, populated.timeToComplete),
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});



app.get("/projects",requireAuth,async(req,res)=>{
  try {
    const projects = await Project.find();
    if(!projects){
      return res.status(400).json({message:"Not found"})
    }
    else{
      return res.status(200).json({projects})
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
})
const PORT = 3000;

intializeDatabase()
  .then(() => {
    console.log("Database connected");
    app.listen(PORT, () => {
      console.log(`Server is running on ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("DB connection failed:", err);
  });

module.exports = app;
