import express from "express";
import prisma from "./prisma/client.js";
import path from "path";
import bcrypt from "bcrypt";

const app = express();
const PORT = 3000;

// 🔥 미들웨어 설정 (순서 중요)
app.use(express.json());
app.use(express.static(path.resolve("public")));

// DB 연결 테스트
app.get("/db-test", async (req, res) => {
  try {
    await prisma.$connect();
    res.send("DB 연결 성공 🎉");
  } catch (err) {
    console.error(err);
    res.status(500).send("DB 연결 실패 😭");
  }
});

// 1. 아이디 중복 확인 (Member / userid)
app.post("/check-username", async (req, res) => {
  const { userid } = req.body;
  const engNumRegex = /^[a-zA-Z0-9]+$/;

  // 유효성 검사
  if (!userid) {
    return res.status(400).json({ available: false, message: "아이디를 입력해주세요." });
  }
  
  // 🔥 글자수 제한 (서버 방어)
  if (userid.length > 20) {
    return res.status(400).json({ available: false, message: "아이디는 20자를 넘을 수 없습니다." });
  }

  if (!engNumRegex.test(userid)) {
    return res.status(400).json({ available: false, message: "영어와 숫자만 가능합니다." });
  }

  try {
    const existingMember = await prisma.member.findUnique({
      where: { userid: userid },
    });

    if (existingMember) {
      return res.status(400).json({ available: false, message: "이미 사용 중인 아이디입니다." });
    }

    res.status(200).json({ available: true, message: "사용 가능한 아이디입니다." });
  } catch (error) {
    console.error("중복확인 에러:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 2. 회원가입 (Member / userid)
app.post("/register", async (req, res) => {
  const { name, userid, password } = req.body;

  // 빈 값 체크
  if (!name || !userid || !password) {
    return res.status(400).json({ message: "모든 값을 입력해주세요." });
  }

  // 🔥 글자수 제한 (서버 방어)
  if (name.length > 10) return res.status(400).json({ message: "이름은 10자를 넘을 수 없습니다." });
  if (userid.length > 20) return res.status(400).json({ message: "아이디는 20자를 넘을 수 없습니다." });
  if (password.length > 20) return res.status(400).json({ message: "비밀번호는 20자를 넘을 수 없습니다." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.member.create({
      data: {
        name,
        userid,
        password: hashedPassword,
      },
    });
    res.status(201).json({ message: "회원가입 성공!" });
  } catch (error) {
    console.error("회원가입 에러:", error);
    res.status(400).json({ message: "회원가입 실패 (아이디 중복 등)" });
  }
});

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`);
});

app.post("/login", async (req, res) => {
  const { userid, password } = req.body;

  // 1. 데이터가 다 왔는지 확인
  if (!userid || !password) {
    return res.status(400).json({ message: "아이디와 비밀번호를 모두 입력해주세요." });
  }

  try {
    // 2. DB에서 아이디로 유저 찾기 (Member 모델 / userid 필드)
    const member = await prisma.member.findUnique({
      where: { userid: userid },
    });

    // 유저가 없으면 에러
    if (!member) {
      return res.status(400).json({ message: "존재하지 않는 아이디입니다." });
    }

    // 3. 비밀번호 비교 (입력한 비번 vs 암호화된 비번)
    const isPasswordCorrect = await bcrypt.compare(password, member.password);

    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "비밀번호가 틀렸습니다." });
    }

    // 4. 로그인 성공!
    // (나중에는 여기서 세션이나 토큰을 발급하지만, 지금은 성공 메시지만!)
    res.status(200).json({ message: "로그인 성공!", name: member.name });

  } catch (error) {
    console.error("로그인 에러:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});