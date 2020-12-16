			$(document).ready(function(){
				
				$("form").submit(function(event){
					var txt = $("input:first").val() ;
					$.ajax({
			        url:"php/class.php",
			        method:"POST",
			        data:{hash:txt},
			        beforeSend:function(data)
			        {
			        	$(".spinner-border").show();
			        	$("#result").hide();
			        },
			        success:function(data)
			        {
			          $(".spinner-border").hide();
			          $("#result").show();
			          $("#result").html(data);
			        }
			      });
					event.preventDefault();
				});
});