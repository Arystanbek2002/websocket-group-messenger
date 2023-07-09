package main

func GetHtmlRegister() []byte {
	return []byte(`<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Messenger</title>
	</head>
	<body>
		<div class="center">
			<h1>Register</h1>
			<div>
				<form id="register-form">
					<label for="username">Username</label>
					<input type="text" id="username" name="username">
					<label for="Password">Password</label>
					<input type="password" id="password" name="password"><br><br>
					<input type="submit" value="Register">
				</form>
			</div>
		</div>
	</body>
	
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

	<script>
	window.onload = function(){
        document.getElementById("register-form").onsubmit = register
    }
	function register(){
        let formData = {
            "username" : document.getElementById("username").value,
            "password" : document.getElementById("password").value
        }
        fetch("registerUser", {
            method: 'post',
            body: JSON.stringify(formData),
            mode: 'cors'
        }).then((response) =>{
            if(response.ok){
				alert('You have registered successfuly')
                window.location.href = "./loginUser"
            }else{
                throw 'unauthorised'
            }
        })//TODO: catch throw

        return false
    }
	</script>



	`)
}
