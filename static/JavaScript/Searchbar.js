
$(document).ready(function(){
  $("#MYInput").on("keyup", function() {
    var value = $(this).val().toLowerCase();
    $("#MYTable tr").filter(function() {
      $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
  });
});
