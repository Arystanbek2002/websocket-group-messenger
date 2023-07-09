package main

import "strconv"

var (
	headString = `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Messenger</title>
	</head>
	<body>
		<div class="center">
			<h1>Users</h1>
			<div style ="padding: 50px">`

	footString = `</div>
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

</script>`
)

func getHtmlUsers(usersResp []*UserResponce) []byte {

	res := ""
	res += headString
	for _, v := range usersResp {
		head := `<div style="display: flex; width : 100%; justify-content: space-between;"><h3>
		`
		foot := `</h3>
		<button onclick="location.href='messenger/` + strconv.Itoa(v.ID) + `'" type="button"> To chat </button>
		</div>`
		res += head + v.UserName + foot
	}
	res += footString
	return []byte(res)
}
