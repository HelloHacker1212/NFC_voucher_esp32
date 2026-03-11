import React, { useState } from "react";

export default function App() {

  const [tab,setTab] = useState("write");
  const [status,setStatus] = useState("Bereit");

  const [name,setName] = useState("");
  const [klasse,setKlasse] = useState("");
  const [tage,setTage] = useState("");

  const [password,setPassword] = useState("");
  const [oldPassword,setOldPassword] = useState("");

  const [tagData,setTagData] = useState(null);

  const api = async (url,method="GET",body=null)=>{
    try{

      const res = await fetch(url,{
        method,
        headers:{ "Content-Type":"application/json"},
        body: body ? JSON.stringify(body):null
      });

      const data = await res.json();

      if(data.ok){
        setStatus("Erfolgreich");
      }else{
        setStatus(data.error);
      }

      return data;

    }catch(e){
      setStatus("Verbindungsfehler");
    }
  }

  const readTag = async ()=>{

    setStatus("Lese NFC Tag...");

    const data = await api("/api/tag/read");

    if(data?.ok){
      setTagData(data);
    }

  }

  const writeTag = async ()=>{

    const text = JSON.stringify({
      name,
      klasse,
      tage
    });

    setStatus("Schreibe Tag...");

    const data = await api("/api/tag/write","POST",{text});

    if(data?.ok){
      setTagData(data);
    }

  }

  const setTagPassword = async ()=>{

    setStatus("Setze Passwort...");

    await api("/api/tag/password/set","POST",{password});

  }

  const removeTagPassword = async ()=>{

    setStatus("Entferne Passwort...");

    await api("/api/tag/password/remove","POST",{oldPassword});

  }

  const eraseTag = async ()=>{

    setStatus("Lösche Tag...");

    await api("/api/tag/erase","POST");

  }

  const healthCheck = async ()=>{

    const data = await api("/api/health");

    if(data?.ok){
      setStatus("API Online - IP: "+data.ip);
    }

  }

  return (

    <div style={styles.page}>

      <h1 style={styles.title}>NFC Voucher System</h1>

      <div style={styles.tabs}>

        <Tab name="write" tab={tab} setTab={setTab}>Voucher schreiben</Tab>
        <Tab name="read" tab={tab} setTab={setTab}>Tag lesen</Tab>
        <Tab name="security" tab={tab} setTab={setTab}>Sicherheit</Tab>
        <Tab name="admin" tab={tab} setTab={setTab}>Admin</Tab>

      </div>

      <div style={styles.card}>

        {tab==="write" && (

          <>
          <h2>Voucher erstellen</h2>

          <input style={styles.input} placeholder="Schülername"
          value={name} onChange={e=>setName(e.target.value)}/>

          <input style={styles.input} placeholder="Klasse"
          value={klasse} onChange={e=>setKlasse(e.target.value)}/>

          <input style={styles.input} type="number"
          placeholder="Anzahl Tage"
          value={tage} onChange={e=>setTage(e.target.value)}/>

          <button style={styles.primaryButton} onClick={writeTag}>
          Auf NFC schreiben
          </button>
          </>
        )}

        {tab==="read" && (

          <>
          <h2>NFC Tag lesen</h2>

          <button style={styles.primaryButton} onClick={readTag}>
          Tag scannen
          </button>

          {tagData && (

            <div style={styles.resultBox}>

              <p><b>UID:</b> {tagData.uid}</p>
              <p><b>Typ:</b> {tagData.tagType}</p>

              <pre style={styles.pre}>
              {tagData.text}
              </pre>

            </div>

          )}
          </>
        )}

        {tab==="security" && (

          <>
          <h2>Tag Sicherheit</h2>

          <input style={styles.input}
          placeholder="Neues Passwort"
          value={password}
          onChange={e=>setPassword(e.target.value)}/>

          <button style={styles.primaryButton}
          onClick={setTagPassword}>
          Passwort setzen
          </button>

          <hr/>

          <input style={styles.input}
          placeholder="Altes Passwort"
          value={oldPassword}
          onChange={e=>setOldPassword(e.target.value)}/>

          <button style={styles.secondaryButton}
          onClick={removeTagPassword}>
          Passwort entfernen
          </button>

          </>
        )}

        {tab==="admin" && (

          <>
          <h2>Admin Tools</h2>

          <button style={styles.secondaryButton}
          onClick={eraseTag}>
          Tag löschen
          </button>

          <button style={styles.primaryButton}
          onClick={healthCheck}>
          API Status prüfen
          </button>

          </>
        )}

      </div>

      <div style={styles.status}>
      {status}
      </div>

    </div>

  );
}

function Tab({name,tab,setTab,children}){

  return(
    <button
      onClick={()=>setTab(name)}
      style={{
        padding:"10px 16px",
        border:"none",
        borderBottom: tab===name ? "3px solid #2c7be5":"3px solid transparent",
        background:"none",
        cursor:"pointer",
        fontWeight: tab===name ? "bold":"normal"
      }}
    >
      {children}
    </button>
  )
}

const styles={

page:{
  fontFamily:"Arial",
  background:"#f5f7fb",
  minHeight:"100vh",
  padding:"40px"
},

title:{
  textAlign:"center",
  marginBottom:"30px"
},

tabs:{
  display:"flex",
  justifyContent:"center",
  gap:"20px",
  marginBottom:"20px"
},

card:{
  maxWidth:"500px",
  margin:"auto",
  background:"white",
  padding:"30px",
  borderRadius:"10px",
  boxShadow:"0 6px 18px rgba(0,0,0,0.1)"
},

input:{
  width:"100%",
  padding:"10px",
  marginBottom:"12px",
  borderRadius:"6px",
  border:"1px solid #ccc",
  fontSize:"14px"
},

primaryButton:{
  width:"100%",
  padding:"12px",
  background:"#2c7be5",
  color:"white",
  border:"none",
  borderRadius:"6px",
  cursor:"pointer",
  marginTop:"10px"
},

secondaryButton:{
  width:"100%",
  padding:"12px",
  background:"#20c997",
  color:"white",
  border:"none",
  borderRadius:"6px",
  cursor:"pointer",
  marginTop:"10px"
},

resultBox:{
  marginTop:"20px",
  background:"#f8f9fa",
  padding:"12px",
  borderRadius:"6px"
},

pre:{
  fontSize:"12px",
  whiteSpace:"pre-wrap"
},

status:{
  textAlign:"center",
  marginTop:"20px",
  color:"#444"
}

}