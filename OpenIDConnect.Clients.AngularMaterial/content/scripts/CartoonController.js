(function () {
    'use strict';

angular.module('CartoonsApp')
.controller('CartoonController', CartoonController);

    CartoonController.$inject = ['$http', 'CartoonsService', 'CharacterService'];
    function CartoonController($http, CartoonsService, CharacterService) {
    var ctrl = this;

        CartoonsService.get().then(function (data) {
            ctrl.cartoons = data;
        });

        CharacterService.get().then(function (data) {
            ctrl.characters = data;
        });
    };
})();