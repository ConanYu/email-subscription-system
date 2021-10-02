let app = new Vue({
    el: '#app',
    data: {
        email: '',
        password: '',
    },
    delimiters: ['${', '}$'],
});

function clickLogin() {
    let email = app.$data.email;
    let password = app.$data.password;
    axios.post('/api/login', {
        email: email,
        password: password,
    }).then(response => {
        if (response.status === 200) {
            window.location.replace('/');
        } else if (response.status === 202) {
            window.location.replace('/register');
        } else {
            throw new Error('non-support status code');
        }
    }).catch(err => {
        console.log(JSON.stringify(err.response));
        alert(err);
    });
}
