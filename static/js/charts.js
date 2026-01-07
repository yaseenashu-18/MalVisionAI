new Chart(document.getElementById("pieChart"), {
  type: "pie",
  data: {
    labels: ["Legitimate", "Malicious"],
    datasets: [{
      data: [75, 25],
      backgroundColor: ["#1abc9c", "#e74c3c"]
    }]
  }
});
