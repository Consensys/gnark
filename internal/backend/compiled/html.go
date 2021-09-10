package compiled

const R1CSTemplate = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-F3w7mX95PdgyTmZZMECAngseQB83DfGTowi0iMjiWaeVhAn4FJkqJByhZMI3AhiU" crossorigin="anonymous">
    <title>R1CS</title>

    <style>
        .coefficient {color:gray;}
		.internal {color:blue;font-weight: bold;}
		.hint {color:purple;font-weight: bold;}
		.public {color:green;font-weight: bold;}
		.secret {color:orange;font-weight: bold;}
		.virtual {color:red;font-weight: bold;}
		.unset {color:red;font-weight: bold;}
    </style>
  </head>
  <body>
   
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-/bQdsTh/da6pkI1MST/rWKFNjaCP5gBSY4sEBT38Q/9RBh9AH40zEOg7Hlq2THRZ" crossorigin="anonymous"></script>
	<div class="container">
	<h1>R1CS</h1>
	{{ $nbHints := len .MHints }}
	{{ $nbConstraints := len .Constraints}}
	<span class="internal">{{.NbInternalVariables}} internal </span> (includes <span class="hint">{{$nbHints}} hints</span>)</br>
	<span class="public">{{.NbPublicVariables}} public</span></br>
	<span class="secret">{{.NbSecretVariables}} secret</span></br>
	<span>{{$nbConstraints}} constraints</span></br>
  <p class="fw-bold">L * R == O</p>
  <p class="fst-italic">-</p>
</div>
<table class="container table table-bordered">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col">L</th>
      <th scope="col">R</th>
      <th scope="col">O</th>
    </tr>
  </thead>
  <tbody>
    {{- range $i, $c := .Constraints}}
    <tr>
      <th scope="row">{{$i}}</th>
	  <td> {{ toHTML $c.L $.Coefficients $.MHints}} </td>
      <td> {{ toHTML $c.R $.Coefficients $.MHints}} </td>
      <td> {{ toHTML $c.O $.Coefficients $.MHints}} </td>
    </tr>
    {{- end }}
  </tbody>
</table>
  </body>
</html>
`

const SparseR1CSTemplate = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-F3w7mX95PdgyTmZZMECAngseQB83DfGTowi0iMjiWaeVhAn4FJkqJByhZMI3AhiU" crossorigin="anonymous">
    <title>SparseR1CS</title>

    <style>
        .coefficient {color:gray;}
		.internal {color:blue;font-weight: bold;}
		.hint {color:purple;font-weight: bold;}
		.public {color:green;font-weight: bold;}
		.secret {color:orange;font-weight: bold;}
		.virtual {color:red;font-weight: bold;}
		.unset {color:red;font-weight: bold;}
    </style>
  </head>
  <body>
   
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-/bQdsTh/da6pkI1MST/rWKFNjaCP5gBSY4sEBT38Q/9RBh9AH40zEOg7Hlq2THRZ" crossorigin="anonymous"></script>
	<div class="container">
	<h1>SparseR1CS</h1>
	{{ $nbHints := len .MHints }}
	{{ $nbConstraints := len .Constraints}}
	
	<span class="internal">{{.NbInternalVariables}} internal </span> (includes <span class="hint">{{$nbHints}} hints</span>)</br>
	<span class="public">{{.NbPublicVariables}} public</span></br>
	<span class="secret">{{.NbSecretVariables}} secret</span></br>
	<span>{{$nbConstraints}} constraints</span></br>
	<p class="fw-bold">L + R + M0*M1 + O + k == 0</p>
  <p class="fst-italic">all variable id are offseted by 1 to match R1CS</p>
</div>

<table class="container table table-bordered">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col">L</th>
      <th scope="col">R</th>
      <th scope="col">M0</th>
	  <th scope="col">M1</th>
	  <th scope="col">O</th>
	  <th scope="col">k</th>
    </tr>
  </thead>
  <tbody>
    {{- range $i, $c := .Constraints}}
    <tr>
		<th scope="row">{{$i}}</th>
	  <td> {{ toHTML $c.L $.Coefficients $.MHints}} </td>
      <td> {{ toHTML $c.R $.Coefficients $.MHints}} </td>
	  <td> {{ toHTML (index $c.M 0) $.Coefficients $.MHints}} </td>
	  <td> {{ toHTML (index $c.M 1)  $.Coefficients $.MHints}} </td>
      <td> {{ toHTML $c.O $.Coefficients $.MHints}} </td>
	  <td> {{ toHTMLCoeff $c.K $.Coefficients }} </td>
    </tr>
    {{- end }}
  </tbody>
</table>
  </body>
</html>
`
