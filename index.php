<!DOCTYPE html>
<html>
<head>
	<title>PHP hash type finder</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Cabin:700">
	<link rel="stylesheet" type="text/css" href="assets/css/bootstrap.min.css">
	<link rel="stylesheet" type="text/css" href="assets/css/main.css">
</head>
<body>
	<div class="container">
  
        <div class="row p-5">
        	<!-- sub -->
            <div class="col-6 offset-3 mb-5">
                    <h1 class="text-white text-center  mb-4">hash type finder</h1>
                    <p class=" text-success text-center">support over 200 hash types.</p>
                <form>    
				<div class="input-group mb-3 ">
				  <input type="text" class="inp form-control" placeholder="ex: 5f4dcc3b5aa765d61d8327deb882cf99" required >
				  <div class="input-group-append">
				   <input type="submit" name="submit" class="btn btn-outline-success" type="button" value="Analyzer">
				  </div>
				</div> 
				</form>               
            </div>
			<!-- result -->
            <div class="col-8 offset-2">

            		<div class="d-flex justify-content-center ">
					<div class="spinner-border  text-success " role="status">
  					<span class="sr-only">Loading...</span>
					</div>
					</div>
					<div id="result" class="text-muted result"> </div>

            </div>
        </div>
<div class="footer text-muted text-center ">By Kadnass-Dz</div>
    </div>

        <script type="text/javascript" charset="UTF-8" src='assets/js/jq.js'></script>
        <script type="text/javascript" charset="UTF-8" src='assets/js/bootstrap.min.js'></script>
        <script type="text/javascript" charset="UTF-8" src='assets/js/find.js'></script>


</body>
</html>