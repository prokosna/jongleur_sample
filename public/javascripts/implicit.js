$(document).ready(function() {
  var uri = location.href;
  var hash = location.hash;

  $('#redirectedUri').val(uri);
  $('#redirectedContent').val(hash);
});
