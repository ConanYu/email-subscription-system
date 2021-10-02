new Vue({
    el: '#app',
    delimiters: ['${', '}$'],
});

function change() {
    axios.post('/api/subscribe').then(response => {
        window.location.reload();
    }).catch(err => {
        console.log(JSON.stringify(err.response));
        alert(err);
    });
}