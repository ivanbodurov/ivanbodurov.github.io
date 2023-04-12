<?php
if (isset($_POST['strtomd5'])) {
  $string_to_md5 = md5($_POST['strtomd5']);
}

if (isset($_POST['strtosha1'])) {
  $string_to_sha1 = sha1($_POST['strtosha1']);
}

if (isset($_POST['strtosha512'])) {
  $string_to_sha512 = hash('sha512',$_POST['strtosha512']);
}



?>

<?php
function encrypt_decrypt($string, $action)
{
    $encrypt_method = 'AES-256-CBC-HMAC-SHA256';

    if (isset($_POST['passphrase'])) {
      $passphrase = substr(hash('sha512', $_POST['passphrase']), 10, 100);
    }
    
    $iv = '2fgf5KJ8g29';
    //$passphrase = 'AA74CDCC2BBRT935136HH7B63C27'; // user defined passphrase
    //$passphrase = hash('sha512', $passphrase);
    //$secret_iv = '5fgf5HJ5g27'; // user defined Initialization Vector
    //$iv = substr(hash('sha512', $secret_iv), 3, 100);
    if ($action == 'encrypt') {
        $output = openssl_encrypt($string, $encrypt_method, $passphrase, 0, $iv);
        $output = base64_encode($output);
    } else if ($action == 'decrypt') {
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $passphrase, 0, $iv);
    }
    if ($output) {
      return $output;
    } else {
      return '<span style="color: #c13232;">Invalid data!</span>';
    }
}

if (isset($_POST['data_to_encrypt'])) {
  $data_to_encrypt = encrypt_decrypt($_POST['data_to_encrypt'], 'encrypt');
}

if (isset($_POST['data_to_decrypt'])) {
  $data_to_decrypt = encrypt_decrypt($_POST['data_to_decrypt'], 'decrypt');
}





// echo "Your Encrypted string is = ". $encrypt_data = encrypt_decrypt('mySecretData', 'encrypt');
// echo "<br>";
// echo "Your Decrypted string is = ". encrypt_decrypt($encrypt_data, 'decrypt');

 ?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>String To Hash Converter</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-+0n0xVW2eSR5OomGNYDnhzAbDsOXxcvSN1TPprVMTNDbiYZCxYbOOl7+AMvyTG2x" crossorigin="anonymous">
    <script type="module" src="https://unpkg.com/ionicons@5.0.0/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule="" src="https://unpkg.com/ionicons@5.0.0/dist/ionicons/ionicons.js"></script>

    <style>
    body {
      background-color: lightblue;
    }
    input[type="text"], input[type="password"], [name="data_to_encrypt"], [name="data_to_decrypt"] {
      background-color: lightblue;
      border: 1px solid black;
      resize: none;
    }

    input[type="text"]:focus, input[type="password"]:focus, [name="data_to_encrypt"]:focus, [name="data_to_decrypt"]:focus, select {
      background-color: lightblue;
      border: 1px solid black;
      resize: none;
    }
    .form-select {
      background-color: lightblue;
      border-color: lightblue;
    }

    .btn {
      border-radius: 10px;
    }
    label {
      cursor: pointer;
    }
      ion-icon {
        position: relative;
        font-size: 1.5em;
        top: 4px;
      }
      .result {
        border-radius: 10px;
        border: 2px solid grey;
        background-color: lightgreen;
        text-indent: 10px;
        overflow: auto;
        resize: none;
      }

      .string_to_md5, .string_to_sha1, .string_to_sha512, .encrypt_string, .decrypt_string {
        border-radius: 10px;
        border: 3px ridge brown;
      }
      a {
        color: darkred;
        position: relative;
        left: 10px;
        text-decoration: none;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>String To Hash Converter & Data encrypter</h1>

      <div class="string_to_md5 mb-3 bg-secondary bg-gradient">
        <form class="" action="" method="post">
          <div class="label">
            <label for="str_to_md5"><i>String to md5:</i></label>
          </div>
          <div class="input-group">
            <input type="text" class="form-control" name="strtomd5" placeholder="Some text.."  aria-label="String.." aria-describedby="button-addon2" required>
            <button class="btn btn-primary" name="button" type="submit" id="button-addon2"><ion-icon name="arrow-forward-circle-outline"></ion-icon></button>
          </div>
        </form>
        <div class="form-group">
          <?php
            if (isset($_POST['strtomd5'])) { ?>
              <label for="md5_result">Result:</label>
              <div id="md5_result" class="result w-100">
                <?=(isset($_POST['strtomd5']))?$string_to_md5:''?>
              </div>
              <a href="https://www.google.com/search?q=<?=$string_to_md5?>" target="_blank">Search with Google</a>
          <?php } ?>
        </div>
      </div>

      <div class="string_to_sha1 mb-3 bg-secondary bg-gradient">
        <form class="" action="" method="post">

          <div class="label">
            <label for="str_to_sha1"><i>String to SHA1:</i></label>
          </div>
          <div class="input-group">
            <input type="text" class="form-control" name="strtosha1" placeholder="Some text.."  aria-label="String.." aria-describedby="button-addon2" required>
            <button class="btn btn-primary" name="button" type="submit" id="button-addon2"><ion-icon name="arrow-forward-circle-outline"></ion-icon></button>
          </div>
        </form>
        <div class="form-group">
          <?php
            if (isset($_POST['strtosha1'])) { ?>
              <label for="sha1_result">Result:</label>
              <div id="sha1_result" class="result w-100">
                <?=(isset($_POST['strtosha1']))?$string_to_sha1:''?>
              </div>
              <a href="https://www.google.com/search?q=<?=$string_to_sha1?>" target="_blank">Search with Google</a>
          <?php } ?>
        </div>
      </div>

      <div class="string_to_sha512 mb-3 bg-secondary bg-gradient">
        <form class="" action="" method="post">

          <div class="label">
            <label for="str_to_sha512"><i>String to SHA512:</i></label>
          </div>
          <div class="input-group">
            <input type="text" class="form-control" name="strtosha512" placeholder="Some text.."  aria-label="String.." aria-describedby="button-addon2" required>
            <button class="btn btn-primary" name="button" type="submit" id="button-addon2"><ion-icon name="arrow-forward-circle-outline"></ion-icon></button>
          </div>
        </form>
        <div class="form-group">
          <?php
            if (isset($_POST['strtosha512'])) { ?>
              <label for="sha512_result">Result:</label>
              <div id="sha512_result" class="result w-100">
                <?=(isset($_POST['strtosha512']))?$string_to_sha512:''?>
              </div>
              <a href="https://www.google.com/search?q=<?=$string_to_sha512?>" target="_blank">Search with Google</a>
          <?php } ?>
        </div>
      </div>

      <!-- Encrypt data -->
      <div class="encrypt_string mb-3 bg-secondary bg-gradient">
        <form class="" action="" method="post">
          <div class="form-group">
            <label for="str_encrypt"><i>Data to encrypt:</i></label>
            <textarea id="str_encrypt" rows="3" class="form-control" name="data_to_encrypt" required></textarea>
          </div>

          <div class="form-group">
            <label for="str_encrypt"><i>Passphrase:</i></label>
            <input type="password" id="passphrase" class="form-control" name="passphrase" required>
          </div>

          <div class="form-group mt-2">
            <button type="submit" class="btn btn-primary w-100" name="button"><ion-icon name="arrow-forward-circle-outline"></ion-icon></button>
          </div>
        </form>
        <div class="form-group">
          <?php
            if (isset($_POST['data_to_encrypt'])) { ?>
              <label for="str_encrypt">Result:</label>
              <?=(isset($_POST['data_to_encrypt']))?'<textarea id="str_encrypt" class="result w-100" readonly>'.$data_to_encrypt.'</textarea>':''?>

          <?php } ?>
        </div>
      </div>


      <!-- Decrypt data -->
      <div class="decrypt_string mb-3 bg-secondary bg-gradient">
        <form class="" action="" method="post">
          <div class="form-group">
            <label for="str_decrypt"><i>Data to decrypt:</i></label>
            <textarea rows="3" id="str_decrypt" class="form-control" name="data_to_decrypt" required></textarea>
          </div>
          <div class="form-group">
            <label for="str_decrypt"><i>Passphrase:</i></label>
            <input type="password" id="passphrase" class="form-control" name="passphrase" required>
          </div>
          <div class="form-group mt-2">
            <button type="submit" class="btn btn-primary w-100" name="button"><ion-icon name="arrow-forward-circle-outline"></ion-icon></button>
          </div>
        </form>
        <div class="form-group">
          <?php
            if (isset($_POST['data_to_decrypt'])) { ?>
              <label for="str_decrypt">Result:</label>

                <?=(isset($_POST['data_to_decrypt']))?'<textarea id="str_decrypt" class="result w-100" readonly>'.$data_to_decrypt.'</textarea>':'';?>

          <?php } ?>
        </div>
      </div>
    </div>


    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js" integrity="sha384-IQsoLXl5PILFhosVNubq5LC7Qb9DXgDA9i+tQ8Zj3iwWAwPtgFTxbJ8NT4GN1R8p" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/js/bootstrap.min.js" integrity="sha384-Atwg2Pkwv9vp0ygtn1JAojH0nYbwNJLPhwyoVbhoPwBhjQPR5VtM2+xf0Uwh9KtT" crossorigin="anonymous"></script>
  </body>
</html>
