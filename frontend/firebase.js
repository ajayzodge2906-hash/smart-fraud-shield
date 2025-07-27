import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { getFirestore, collection, addDoc, Timestamp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDHekv8_qinn7vIj7yBHU_DpL18jusoSIA",
  authDomain: "smart-fraud-shield.firebaseapp.com",
  projectId: "smart-fraud-shield",
  storageBucket: "smart-fraud-shield.firebasestorage.app",
  messagingSenderId: "889709392699",
  appId: "1:889709392699:web:d2a653e8ede3141af17d1e"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

export async function reportFraudMessage(messageText, score) {
  try {
    await addDoc(collection(db, "fraud_reports"), {
      message: messageText,
      score: score,
      reportedAt: Timestamp.now()
    });
    alert("✅ Fraud message successfully reported and saved!");
  } catch (error) {
    console.error("❌ Error reporting fraud message:", error);
    alert("Something went wrong while reporting.");
  }
}
