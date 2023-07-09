package main

func GetHtmlIndex() []byte {
	return []byte(`<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Messenger</title>
	</head>
	<body>
		<div class="center">
			<h1>Messenger</h1>
			<ul>
  			<li><h3><a href="conversation">My conversations</a></h3></li>
  			<li><h3><a href="user">Users</a></h3></li>
			</ul>
		</div>
	</body>
	
	<script>
		
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
	`)
}
