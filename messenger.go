package main

import (
	"fmt"
	"strconv"
)

var htmlString1 = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Messenger</title>
</head>
<body>
<div class="center">
    <h1>Messenger</h1>
    <h3 id="chat-name">Currently in chat: general</h3>
    <h3 id="connection-header">Connected to chat: false</h3>
    <form id="chatroom-selection">
        <label for="chatroom">Chatroom</label>
        <input type="text" name="chatroom" id="chatroom"><br><br>
        <input type="submit" value="Change chatroom">
    </form>
    <br>
    <br>

    <textarea name="messagearea" id="chatmessages" cols="50" rows="7" readonly placeholder="Welcome to chat">`

var htmlString2 = `</textarea>
<br>
<br>
<form id="chatroom-message" onsubmit="sendMessage">
    <label for="message">Message:</label>
    <br>
    <input type="text" id="message" name="message"><br><br>
    <input type="submit" value="Send message">
</form>
<br><br>
</div>
</body>

<script>
var selectedChat = "general"
var direct = `

var htmlString3 = `
class Event {
constructor(type, payload){
    this.type = type;
    this.payload = payload;
}
}

class sendMessageEvent {
constructor(from, message){
    this.from = from;
    this.direct_id = direct
    this.message = message;
}
}

class sendMessagePost {
    constructor(message){
        this.direct_id = direct
        this.value = message;
    }
}

class newMessageEvent {
constructor(from, message, sent){
    this.from = from;
    this.message = message;
    this.sent = sent;
}
}

function routeEvent(event){
if(event.type === undefined){
    alert("no type field in event")
}

switch(event.type){
    case "new_message":
        const messageEvent = Object.assign(new newMessageEvent, event.payload)
        appendChatMessage(messageEvent)
        break
    default:
        alert("unsupproted message type")
        break
}
}

function appendChatMessage(messageEvent){
var date = new Date(messageEvent.sent)
const formatedMsg = date.toLocaleString() + " " + messageEvent.from + ": " + messageEvent.message
document.getElementById("chatmessages").innerHTML = document.getElementById("chatmessages").innerHTML + "\n" + formatedMsg
document.getElementById("chatmessages").scrollTop = document.getElementById("chatmessages").scrollHeight
}

function sendEvent(eventName, payload){
const event = new Event(eventName, payload)
conn.send(JSON.stringify(event))
}

function changeChatRoom(){
var newChat = document.getElementById("chatroom").value
if(newChat != null && newChat != selectedChat){
    console.log(newChat)
    selectedChat = newChat
}
return false;
}

function sendMessage(){  
    const sendmessagepost = new sendMessagePost(document.getElementById("message").value)
    fetch("http://localhost:8080/sendmessage", {
        method: 'post',
        body: JSON.stringify(sendmessagepost),
        mode: 'cors'
    }).then((response) =>{
        if(response.ok){
            
        }else{
            alert('Error!!!')
            return false
        }
    })//TODO: catch throw
var newMessage = document.getElementById("message")
var outgoingEvent = new sendMessageEvent("username", newMessage.value)
if(newMessage != null){
    sendEvent("send_message", outgoingEvent )
    return false;        
}
}

function connectWebSocket(){
if(window["WebSocket"]){
    console.log("Support websockets")
    conn = new WebSocket("ws://" + document.location.host + "/ws")

    conn.onopen = function(evt){
        document.getElementById("connection-header").innerHTML = "Connected to chat: true"
    }

    conn.onmessage = function(evt){
        const eventData = JSON.parse(evt.data)
        const event = Object.assign(new Event, eventData)
        routeEvent(event)
    }

    conn.onclose = function(evt){
        document.getElementById("connection-header").innerHTML = "Connected to chat: false"
    }
}else{
    alert("WebSockets are not supported by browser")
}
}



window.onload = function(){
    document.getElementById("chatroom-selection").onsubmit = changeChatRoom
    document.getElementById("chatroom-message").onsubmit = sendMessage

    connectWebSocket()
}
</script>

<style type="text/css">
body {
overflow: hidden;
padding: 0;
margin: 0;
width: 100%;
height: 100%;
background-color: rgb(225, 239, 207);
}

.center {
margin: auto;
margin-top: 20px;
width: 50%;
padding: 10px;
background-color: rgb(148, 226, 141);
}
</style>

</html>
`

func GetHtmlMessenger(messages []*Message, users map[int]*User, directID int) []byte {
	res := ""
	res += htmlString1
	for _, v := range messages {
		res += fmt.Sprintf("%s %d-%d-%d %d:%d\n%s\n\n", users[v.From].UserName, v.CreatedAt.Day(), v.CreatedAt.Month(), v.CreatedAt.Year(), v.CreatedAt.Hour(), v.CreatedAt.Minute(), v.Value)
	}
	res += htmlString2 + strconv.Itoa(directID) + htmlString3
	return []byte(res)
}
