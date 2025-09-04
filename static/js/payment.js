
function initRazorpay(orderData){
  if(!orderData || !orderData.order_id){ alert("Order not ready"); return; }
  var options = {
      "key": orderData.key_id,
      "amount": orderData.amount,
      "currency": "INR",
      "name": "PlatinumStay",
      "description": "Rent payment",
      "order_id": orderData.order_id,
      "handler": function (response){
          const form = document.createElement('form');
          form.method = 'POST';
          form.action = '/pay/confirm';
          for (const [k,v] of Object.entries(response)){
            const input = document.createElement('input');
            input.type='hidden'; input.name=k; input.value=v; form.appendChild(input);
          }
          document.body.appendChild(form);
          form.submit();
      },
      "prefill": {},
      "theme": {"color": "#2563eb"}
  };
  var rzp1 = new Razorpay(options);
  rzp1.open();
}
